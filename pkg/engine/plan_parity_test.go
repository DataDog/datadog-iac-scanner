/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfparser "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	"github.com/stretchr/testify/require"
)

// The scanner must report the same resource addresses Terraform puts in a
// plan: every fixture carries a checked-in `tofu show -json` plan, and the
// addresses the scanner's expansion produces must equal the plan's
// resource_changes addresses. Fixtures were generated with OpenTofu (tofu
// plan -out=plan.bin && tofu show -json plan.bin) over configurations that
// plan offline (terraform_data, null_data_source).
func TestPlanAddressParity(t *testing.T) {
	fixtures := []string{"counts", "modules", "nested", "special", "tfjson"}
	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			dir := filepath.Join("testdata", "plan_parity", fixture)

			var files model.FileMetadatas
			var walk func(string)
			walk = func(dir string) {
				subEntries, err := os.ReadDir(dir)
				require.NoError(t, err)
				for _, e := range subEntries {
					full := filepath.Join(dir, e.Name())
					if e.IsDir() {
						walk(full)
						continue
					}
					if strings.HasSuffix(full, ".tf") || strings.HasSuffix(full, ".tf.json") {
						files = append(files, parsePlanParityFile(t, full)...)
					}
				}
			}
			walk(dir)

			planJSON, err := os.ReadFile(filepath.Join(dir, "plan.json"))
			require.NoError(t, err)
			var plan struct {
				ResourceChanges []struct {
					Address string `json:"address"`
					Change  struct {
						Actions []string `json:"actions"`
					} `json:"change"`
				} `json:"resource_changes"`
			}
			require.NoError(t, json.Unmarshal(planJSON, &plan))
			want := map[string]bool{}
			for _, rc := range plan.ResourceChanges {
				destroyOnly := len(rc.Change.Actions) == 1 && rc.Change.Actions[0] == "delete"
				if destroyOnly {
					continue
				}
				want[rc.Address] = true
			}

			if fixture == "counts" {
				// The fixture's data source is not tracked in the plan's
				// resource_changes (no read is planned for it); it keeps the
				// unindexed address. Every address the plan reports must be
				// covered.
				got := expansionAddresses(t, dir, files)
				for addr := range want {
					require.Contains(t, got, addr, "plan address missing from the scanner")
				}
				require.Contains(t, got, "data.null_data_source.d",
					"a data source the plan does not track keeps the unindexed address")
				return
			}
			if fixture == "modules" || fixture == "nested" {
				// Module-interior resources get their module-prefixed
				// addresses through evaluation. The module files are also
				// scanned as written (unresolved for_each over module
				// variables keeps the unindexed form), so the engine run has
				// extras beyond the plan; every plan address must be covered.
				got := inspectAddresses(t, t.TempDir(), files)
				for addr := range want {
					if strings.Contains(addr, "terraform_data") {
						require.Contains(t, got, addr, "plan address missing from the scanner")
					}
				}
				return
			}
			got := expansionAddresses(t, dir, files)
			require.Equal(t, sortedKeys(want), sortedKeys(got))
		})
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func parsePlanParityFile(t *testing.T, path string) model.FileMetadatas {
	t.Helper()
	content, err := os.ReadFile(filepath.Clean(path))
	require.NoError(t, err)
	_, docs, _, _, err := tfparser.NewDefault().Parse(context.Background(), content, path, false, 15)
	require.NoError(t, err)
	var out model.FileMetadatas
	for i, doc := range docs {
		fm := &model.FileMetadata{
			ID:             filepath.Clean(path) + "#" + string(rune('0'+i)),
			ScanID:         "test",
			OriginalData:   string(content),
			ExpansionLayer: i,
			Document:       doc,
			FilePath:       path,
			Kind:           model.KindTerraform,
			Platform:       "Terraform",
			Expansions:     model.ParseExpansions(doc["_dd_expansions"]),
		}
		delete(doc, "_dd_expansions")
		out = append(out, fm)
	}
	return out
}

// expansionAddresses collects every Terraform address the scanner's expansion
// produces for the parsed files: a block's expansion plan addresses when it
// has one, the unindexed form otherwise. Blocks whose expansion resolved to
// zero instances produce no address, matching a plan.
func expansionAddresses(t *testing.T, root string, files model.FileMetadatas) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, f := range files {
		if f == nil || f.Document == nil {
			continue
		}
		for _, exp := range f.Expansions {
			for _, addr := range exp.Addresses {
				out[addr] = true
			}
		}
		// Blocks without a resolved expansion keep the unindexed address;
		// expanded blocks are already covered by their plan addresses.
		expandedTypes := map[string]bool{}
		for _, exp := range f.Expansions {
			expandedTypes[exp.Type+"\x00"+exp.Name] = true
		}
		if resource, ok := asStringMap(f.Document["resource"]); ok {
			for typ, blocksRaw := range resource {
				blocks, ok := asStringMap(blocksRaw)
				if !ok {
					continue
				}
				for name := range blocks {
					if expandedTypes[typ+"\x00"+name] {
						continue
					}
					out[typ+"."+name] = true
				}
			}
		}
		if data, ok := asStringMap(f.Document["data"]); ok {
			for typ, blocksRaw := range data {
				blocks, ok := asStringMap(blocksRaw)
				if !ok {
					continue
				}
				for name := range blocks {
					out["data."+typ+"."+name] = true
				}
			}
		}
	}
	return out
}

// inspectAddresses runs the full engine over the files with a rule that
// matches every terraform_data resource, and returns the resource addresses
// the findings report. The files are materialized under root so module
// evaluation resolves local module calls against the real directory tree.
func inspectAddresses(t *testing.T, root string, files model.FileMetadatas) map[string]bool {
	t.Helper()
	for _, f := range files {
		dest := filepath.Join(root, f.FilePath)
		require.NoError(t, os.MkdirAll(filepath.Dir(dest), 0o755))
		require.NoError(t, os.WriteFile(dest, []byte(f.OriginalData), 0o644))
	}
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".tf") || strings.HasSuffix(path, ".tf.json") {
			files = append(files, parsePlanParityFile(t, path)...)
		}
		return nil
	})
	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "all_data_rule", Platform: "terraform",
			Content: `package datadog

DatadogPolicy contains result if {
	some name, i
	r := input.document[i].resource.terraform_data[name]
	result := {
		"documentId": input.document[i].id,
		"resourceType": "terraform_data",
		"resourceName": name,
		"searchKey": sprintf("terraform_data[%s].input", [name]),
	}
}
`,
			InputData: "{}",
			Metadata:  map[string]interface{}{"id": "all-data-rule"}, Aggregation: 1,
		}},
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	out := map[string]bool{}
	for i := range vulns {
		require.NotEmpty(t, vulns[i].ResourceAddress, vulns[i].SearchKey)
		out[vulns[i].ResourceAddress] = true
	}
	return out
}
