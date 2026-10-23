/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/stretchr/testify/require"
)

// cardinalityFixture writes a repository whose every aws_s3_bucket instance
// triggers aclRule once: roots calling a module expanded twice over, plus
// expanded and plain resources of the roots themselves.
func cardinalityFixture(t *testing.T, roots int, distinct bool) (string, model.FileMetadatas, int) {
	t.Helper()
	repo := t.TempDir()
	write := func(path, src string) string {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
		return path
	}
	paths := []string{
		write(filepath.Join(repo, "modules", "leaf", "main.tf"), `
variable "name" {}
resource "aws_s3_bucket" "b" {
  count  = 2
  bucket = "${var.name}-${count.index}"
  acl    = "public-read"
}
`),
		write(filepath.Join(repo, "modules", "mid", "main.tf"), `
variable "name" {}
module "leaf" {
  source   = "../leaf"
  for_each = toset(["x", "y", "z"])
  name     = "${var.name}-${each.key}"
}
`),
	}
	for i := range roots {
		name := "shared"
		if distinct {
			name = fmt.Sprintf("root%d", i)
		}
		paths = append(paths, write(filepath.Join(repo, fmt.Sprintf("r%02d", i), "main.tf"), fmt.Sprintf(`
module "mid" {
  source = "../modules/mid"
  count  = 2
  name   = "%s-${count.index}"
}
resource "aws_s3_bucket" "counted" {
  count  = 2
  bucket = "%s-counted-${count.index}"
  acl    = "public-read"
}
resource "aws_s3_bucket" "plain" {
  bucket = "%s-plain"
  acl    = "public-read"
}
`, name, name, name)))
	}
	var files model.FileMetadatas
	for _, p := range paths {
		files = append(files, parseTerraform(t, p)...)
	}
	// Per root: 2 mids x 3 leaves x 2 buckets, 2 counted and 1 plain bucket.
	return repo, files, roots * (2*3*2 + 2 + 1)
}

func aclInspector(t *testing.T, repo string) *Inspector {
	t.Helper()
	return newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "acl_rule", Content: aclRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "acl-rule"}, Aggregation: 1,
		}},
		repoPath:      repo,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
}

// findingKey identifies a finding by everything that sets one customer
// resource apart from another: the document it was found in, which carries
// the instance, the call chain, the file and the line.
func findingKey(v *model.Vulnerability) string {
	return strings.Join([]string{filepath.Base(filepath.Dir(v.FileName)), v.FileID, v.ModuleCallChain, fmt.Sprint(v.Line), v.SearchKey}, "\t")
}

func inspectFindings(t *testing.T, workers int, repo string, files model.FileMetadatas) ([]string, *Inspector) {
	t.Helper()
	previous := rootEvalWorkers
	rootEvalWorkers = workers
	defer func() { rootEvalWorkers = previous }()
	ins := aclInspector(t, repo)
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	keys := make([]string, len(vulns))
	for i := range vulns {
		keys[i] = findingKey(&vulns[i])
	}
	sort.Strings(keys)
	return keys, ins
}

// Every instance is one finding: none is missing, none is reported twice, and
// the source blocks the instances replace are not reported as written.
func TestInspect_EveryInstanceIsOneFinding(t *testing.T) {
	for _, distinct := range []bool{false, true} {
		t.Run(fmt.Sprintf("distinct=%t", distinct), func(t *testing.T) {
			repo, files, want := cardinalityFixture(t, 3, distinct)
			keys, ins := inspectFindings(t, 1, repo, files)
			require.Len(t, keys, want, "one finding per instance")
			seen := map[string]bool{}
			for _, k := range keys {
				require.False(t, seen[k], "duplicate finding %s", k)
				seen[k] = true
			}
			byDir := map[string]int{}
			for _, k := range keys {
				byDir[strings.Split(k, "\t")[0]]++
			}
			// 36 leaf instances, and per root 2 counted instances plus the plain one.
			require.Equal(t, 36, byDir["leaf"])
			for i := range 3 {
				require.Equal(t, 3, byDir[fmt.Sprintf("r%02d", i)])
			}
			require.True(t, ins.ModuleEvaluationReport().Complete())
		})
	}
}

// Roots evaluated concurrently produce exactly the findings of a serial run.
func TestInspect_ConcurrentRootsMatchSerialFindings(t *testing.T) {
	repo, files, want := cardinalityFixture(t, 9, false)
	serial, _ := inspectFindings(t, 1, repo, files)
	require.Len(t, serial, want)
	for range 3 {
		concurrent, _ := inspectFindings(t, 4, repo, files)
		require.Equal(t, serial, concurrent)
	}
}

// Past an explicit instance limit the scan says it is incomplete, and keeps
// scanning as written what it did not instantiate instead of dropping it.
func TestInspect_InstanceLimitReportsIncomplete(t *testing.T) {
	repo, files, _ := cardinalityFixture(t, 3, true)
	ins := aclInspector(t, repo)
	ins.SetModuleEvaluationLimits(tfeval.Limits{MaxInstances: 20})
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	inc := ins.ModuleEvaluationReport().Incomplete()
	require.Len(t, inc, 1)
	require.Equal(t, tfeval.ReasonInstanceLimit, inc[0].Reason)
	// Each root that was not evaluated still has its blocks scanned as
	// written: the module bucket block and its own two blocks at least.
	require.NotEmpty(t, vulns)
}
