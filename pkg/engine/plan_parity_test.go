/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	jsonparser "github.com/DataDog/datadog-iac-scanner/pkg/parser/json"
	"github.com/stretchr/testify/require"
)

// These checked-in plans come from #413 (Terraform 1.12.6, as recorded in
// terraform_version). Compare the complete address multiset for the fixture's
// scanned resources, including prior-state data: resource_changes alone omits
// already-resolved data sources. This proves equality for these small fixtures,
// not general plan parity for unknown values, providers or capped expansions.
func TestPlanAddressParity(t *testing.T) {
	for _, fixture := range []string{"counts", "modules", "nested", "special", "tfjson"} {
		t.Run(fixture, func(t *testing.T) {
			root, err := filepath.Abs(filepath.Join("testdata", "plan_parity", fixture))
			require.NoError(t, err)
			var files model.FileMetadatas
			require.NoError(t, filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !entry.IsDir() && (strings.HasSuffix(path, ".tf") || strings.HasSuffix(path, ".tf.json")) {
					files = append(files, parseTerraform(t, path)...)
				}
				return nil
			}))
			planPath := filepath.Join(root, "plan.json")
			raw, err := os.ReadFile(planPath)
			require.NoError(t, err)
			var plan struct {
				Changes []struct{ Address string } `json:"resource_changes"`
				Prior   struct {
					Values struct {
						Root struct {
							Resources []struct{ Address, Mode string }
						} `json:"root_module"`
					} `json:"values"`
				} `json:"prior_state"`
			}
			require.NoError(t, json.Unmarshal(raw, &plan))
			var want []string
			for _, change := range plan.Changes {
				want = append(want, change.Address)
			}
			for _, resource := range plan.Prior.Values.Root.Resources {
				if resource.Mode == "data" {
					want = append(want, resource.Address)
				}
			}
			var got []string
			for _, finding := range addressFindings(t, root, files) {
				require.Empty(t, finding.ResourceAddressFallback)
				got = append(got, finding.ResourceAddress)
			}
			require.ElementsMatch(t, want, got, "config findings must equal the complete fixture address multiset")

			parser := &jsonparser.Parser{}
			_, docs, _, _, err := parser.Parse(context.Background(), raw, planPath, false, 0)
			require.NoError(t, err)
			require.Len(t, docs, 1)
			planFile := &model.FileMetadata{ID: "plan", Kind: model.KindTerraformPlan, Platform: "terraform",
				FilePath: planPath, Document: docs[0], LineInfoDocument: docs[0], OriginalData: string(raw)}
			got = nil
			for _, finding := range addressFindings(t, root, model.FileMetadatas{planFile}) {
				require.Empty(t, finding.ResourceAddressFallback)
				got = append(got, finding.ResourceAddress)
			}
			require.ElementsMatch(t, want, got, "parsed plans retain their authoritative addresses")
		})
	}
}
