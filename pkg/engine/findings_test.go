/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/storage"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

// instanceFindings are the findings the instances of one count-expanded
// resource block raise: one per instance document, all of one identity.
func instanceFindings(instances int, line int) []model.Vulnerability {
	out := make([]model.Vulnerability, 0, instances)
	for i := 0; i < instances; i++ {
		out = append(out, model.Vulnerability{
			FileName: "modules/app/main.tf", Platform: "Terraform", QueryID: "q",
			ResourceType: "aws_s3_bucket", ResourceName: "replica",
			ModuleCallChain: "stack/main.tf|module.app",
			Line:            line + i, SearchKey: "aws_s3_bucket[replica].acl",
		})
	}
	return out
}

func TestFindingSet_KeepsTheLastFindingOfEachIdentity(t *testing.T) {
	set := newFindingSet(true)
	raised := instanceFindings(3, 10)
	other := raised[0]
	other.ResourceName = "primary"
	raised = append(raised, other)

	for i := range raised {
		set.add(&raised[i])
	}

	require.Len(t, set.out, 2)
	require.Equal(t, 12, set.out[0].Line, "the last instance's finding is the one kept")
	require.Equal(t, "primary", set.out[1].ResourceName, "a different identity is kept on its own")
}

// What the set keeps must be what the scan reports, so that keeping findings
// as they are decoded cannot change a report.
func TestFindingSet_KeepsWhatStorageReports(t *testing.T) {
	ctx := context.Background()
	raised := append(instanceFindings(3, 10), instanceFindings(2, 40)...)
	raised[3].ResourceName = "other"
	raised[4].ResourceName = "other"

	direct := storage.NewMemoryStorage()
	require.NoError(t, direct.SaveVulnerabilities(ctx, append([]model.Vulnerability(nil), raised...)))
	want, err := direct.GetVulnerabilities(ctx, "")
	require.NoError(t, err)

	set := newFindingSet(true)
	for i := range raised {
		set.add(&raised[i])
	}
	reduced := storage.NewMemoryStorage()
	require.NoError(t, reduced.SaveVulnerabilities(ctx, set.out))
	got, err := reduced.GetVulnerabilities(ctx, "")
	require.NoError(t, err)

	require.Equal(t, want, got)
	require.Equal(t, want, set.out, "nothing is left for storage to deduplicate")
}

// Two instances of one block share an identity, and a caller deduplicated
// onto the earlier instance is not a caller of the later one. Routing after
// keeping one finding would report only the later instance's callers.
func TestFindingSet_RoutesBeforeKeepingAnIdentity(t *testing.T) {
	chain := "stack/main.tf|module.app"
	finding := func(docID string, line int) model.Vulnerability {
		return model.Vulnerability{
			FileID: docID, FileName: "modules/app/main.tf", Platform: "Terraform", QueryID: "q",
			ResourceType: "aws_s3_bucket", ResourceName: "replica", ModuleCallChain: chain, Line: line,
		}
	}
	routing := newFindingRouting(map[string][]extraCallerInfo{
		"doc-early": {{callChain: "other/main.tf|module.app", docID: "doc-other"}},
	}, nil, nil, "/repo")

	set := newFindingSet(true)
	early, late := finding("doc-early", 1), finding("doc-late", 2)
	set.addRouted(context.Background(), &Inspector{}, routing, &early)
	set.addRouted(context.Background(), &Inspector{}, routing, &late)

	got := map[string]int{}
	for i := range set.out {
		got[set.out[i].ModuleCallChain] = set.out[i].Line
	}
	require.Equal(t, map[string]int{
		chain:                      2,
		"other/main.tf|module.app": 1,
	}, got)
}

func TestFindingSet_KeepsEveryFindingWhenNotCompacting(t *testing.T) {
	set := newFindingSet(false)
	raised := instanceFindings(3, 10)

	for i := range raised {
		set.add(&raised[i])
	}

	require.Equal(t, raised, set.out, "every decoded finding is kept, identity included")
}

func TestNewFindingRouting_IndexesRootCallersOnly(t *testing.T) {
	repo := t.TempDir()
	files := model.FileMetadatas{
		{FilePath: filepath.Join(repo, "stack", "main.tf")},
		{FilePath: filepath.Join(repo, "modules", "app", "main.tf"), ModuleCallChain: "stack/main.tf|module.app"},
		nil,
	}
	routing := newFindingRouting(nil, nil, files, repo)
	require.Len(t, routing.callers, 1)
	require.Contains(t, routing.callers, "stack/main.tf")
}

// openIngressRule fires once per ingress block open to the internet, mirroring
// the shape of production rules such as unknown_port_exposed_to_internet: one
// result per violating block of a resource, not one per resource.
const openIngressRule = `package datadog

DatadogPolicy contains result if {
	some name, i
	sg := input.document[i].resource.aws_security_group[name]
	some j
	ingress := sg.ingress[j]
	some cidr_block in ingress.cidr_blocks
	cidr_block == "0.0.0.0/0"

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_security_group",
		"resourceName": name,
		"searchKey": sprintf("aws_security_group[%s].ingress[%d].cidr_blocks", [name, j]),
	}
}
`

// twoIngressBlocks is one aws_security_group with two independently open
// ingress blocks: two genuine violations of openIngressRule on one resource,
// at two different lines.
func twoIngressBlocks(t *testing.T) (model.FileMetadatas, string) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "main.tf")
	require.NoError(t, os.WriteFile(path, []byte(`
resource "aws_security_group" "sg" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 3389
    to_port     = 3389
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`), 0o644))
	return parseTerraform(t, path), root
}

func openIngressQueries() []model.QueryMetadata {
	return []model.QueryMetadata{{
		Query:       "open_ingress_rule",
		Content:     openIngressRule,
		InputData:   "{}",
		Platform:    "terraform",
		Metadata:    map[string]interface{}{"id": "open-ingress", "platform": "Terraform"},
		Aggregation: 1,
	}}
}

// Inspect returns every decoded finding unless compaction is enabled.
func TestInspect_TwoViolationsOnOneResource_InspectReturnsBoth(t *testing.T) {
	files, root := twoIngressBlocks(t)
	ins := newTestInspector(t, inspectorOpts{
		queries:       openIngressQueries(),
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 2, "Inspect must return every decoded finding, one per violating ingress block")
	require.NotEqual(t, vulns[0].Line, vulns[1].Line, "the two violations are at different lines")
	require.Equal(t, model.FindingIdentity(&vulns[0]), model.FindingIdentity(&vulns[1]),
		"both violations are on the same resource and rule, so they share an identity")
}

// The scan path that retains findings for storage opts into decode-time
// identity reduction, so it keeps only the last of the two violations: the
// same reduction storage itself would apply at the end of the scan.
func TestInspect_TwoViolationsOnOneResource_CompactedScanPathKeepsOne(t *testing.T) {
	files, root := twoIngressBlocks(t)
	ins := newTestInspector(t, inspectorOpts{
		queries:       openIngressQueries(),
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	ins.SetCompactFindingsAtDecode(true)

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 1, "the scan path that retains findings for storage keeps one finding per identity")
	require.Equal(t, 11, vulns[0].Line, "the last decoded violation (port 3389) is the one kept")
}
