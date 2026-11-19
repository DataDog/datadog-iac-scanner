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
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

const variableWithoutDescriptionRule = `package datadog

DatadogPolicy contains result if {
	some i
	doc := input.document[i]
	some name
	v := doc.variable[name]
	not v.description

	result := {
		"documentId": doc.id,
		"resourceType": "variable",
		"resourceName": name,
		"searchKey": sprintf("variable.%s", [name]),
	}
}
`

const bucketRule = `package datadog

DatadogPolicy contains result if {
	some i
	doc := input.document[i]
	some name
	doc.resource.aws_s3_bucket[name]

	result := {
		"documentId": doc.id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s]", [name]),
	}
}
`

func scanSharedModule(t *testing.T, roots int) (variables, buckets int) {
	t.Helper()
	dir := t.TempDir()
	modDir := filepath.Join(dir, "modules", "svc")
	require.NoError(t, os.MkdirAll(modDir, 0o755))
	modPath := filepath.Join(modDir, "main.tf")
	require.NoError(t, os.WriteFile(modPath, []byte(`
variable "name" {}
resource "aws_s3_bucket" "b" { bucket = var.name }
`), 0o644))
	var files model.FileMetadatas
	files = append(files, parseTerraform(t, modPath)...)
	for i := 0; i < roots; i++ {
		rootDir := filepath.Join(dir, "envs", fmt.Sprintf("r%02d", i))
		require.NoError(t, os.MkdirAll(rootDir, 0o755))
		path := filepath.Join(rootDir, "main.tf")
		require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf(`
module "svc" {
  source = "../../modules/svc"
  name   = "r%02d"
}
`, i)), 0o644))
		files = append(files, parseTerraform(t, path)...)
	}

	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{
			{
				Query: "variable_without_description", Content: variableWithoutDescriptionRule, InputData: "{}", Platform: "terraform",
				Metadata: map[string]interface{}{"id": "variable-rule", "platform": "Terraform"}, Aggregation: 1,
			},
			{
				Query: "bucket", Content: bucketRule, InputData: "{}", Platform: "terraform",
				Metadata: map[string]interface{}{"id": "bucket-rule", "platform": "Terraform"}, Aggregation: 1,
			},
		},
		repoPath:      dir,
		vb:            DefaultVulnerabilityBuilder,
		tracker:       &tracker.CITracker{},
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	for i := range vulns {
		switch vulns[i].QueryID {
		case "variable-rule":
			variables++
		case "bucket-rule":
			buckets++
		}
	}
	return variables, buckets
}

// A variable written once in a shared module is one finding however many
// roots call the module; each call's resource instance is still its own.
func TestInspect_SharedModuleFindingsDoNotGrowWithRoots(t *testing.T) {
	for _, roots := range []int{1, 3, 8} {
		variables, buckets := scanSharedModule(t, roots)
		require.Equal(t, 1, variables, "roots=%d", roots)
		require.Equal(t, roots, buckets, "roots=%d", roots)
	}
}
