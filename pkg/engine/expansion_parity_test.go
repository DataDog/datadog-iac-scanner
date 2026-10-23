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
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

const expansionRules = aclRule

const expansionConfig = `
locals {
  acls = { one = "public-read", two = "private" }
}

resource "aws_s3_bucket" "plain" {
  acl = "public-read"
}

resource "aws_s3_bucket" "counted" {
  count = 3
  acl   = count.index == 2 ? "public-read" : "private"
}

resource "aws_s3_bucket" "keyed" {
  for_each = local.acls
  acl      = each.value
}

resource "aws_s3_bucket" "listed" {
  for_each = toset(["a", "b"])
  acl      = each.key == "b" ? "public-read" : "private"
}

resource "aws_s3_bucket" "constant" {
  count = 2
  acl   = "public-read"
}

resource "aws_s3_bucket" "disabled" {
  count = 0
  acl   = "public-read"
}

resource "aws_s3_bucket" "empty" {
  for_each = {}
  acl      = "public-read"
}
`

func expansionFindings(t *testing.T, root string, files model.FileMetadatas) []model.Vulnerability {
	t.Helper()
	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "acl_rule", Content: expansionRules, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "acl-rule"}, Aggregation: 1,
		}},
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	return vulns
}

// A block expands into the same findings whether it is scanned in place or
// instantiated by a module call.
func TestInspect_ExpansionFindingsMatchBetweenFlatAndModule(t *testing.T) {
	for _, config := range []struct{ name, source string }{
		{"main.tf", expansionConfig},
		{"main.tf.json", `{
 "resource": {"aws_s3_bucket": {
  "plain": {"acl": "public-read"},
  "counted": {"count": 3, "acl": "${count.index == 2 ? \"public-read\" : \"private\"}"},
  "keyed": {"for_each": {"one": "public-read", "two": "private"}, "acl": "${each.value}"},
  "listed": {"for_each": "${toset([\"a\", \"b\"])}", "acl": "${each.key == \"b\" ? \"public-read\" : \"private\"}"},
  "constant": {"count": 2, "acl": "public-read"},
  "disabled": {"count": 0, "acl": "public-read"},
  "empty": {"for_each": {}, "acl": "public-read"}
 }}
}`},
	} {
		t.Run(config.name, func(t *testing.T) { expansionParity(t, config.name, config.source) })
	}
}

func expansionParity(t *testing.T, name, source string) {
	t.Helper()
	root := t.TempDir()

	flatPath := filepath.Join(root, "flat", name)
	require.NoError(t, os.MkdirAll(filepath.Dir(flatPath), 0o755))
	require.NoError(t, os.WriteFile(flatPath, []byte(source), 0o644))
	flat := expansionFindings(t, filepath.Dir(flatPath), parseTerraform(t, flatPath))

	rootPath := filepath.Join(root, "stack", "main.tf")
	modPath := filepath.Join(root, "modules", "buckets", name)
	require.NoError(t, os.MkdirAll(filepath.Dir(rootPath), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Dir(modPath), 0o755))
	require.NoError(t, os.WriteFile(rootPath, []byte("module \"buckets\" {\n  source = \"../modules/buckets\"\n}\n"), 0o644))
	require.NoError(t, os.WriteFile(modPath, []byte(source), 0o644))
	var files model.FileMetadatas
	files = append(files, parseTerraform(t, rootPath)...)
	files = append(files, parseTerraform(t, modPath)...)
	module := expansionFindings(t, root, files)

	// plain and the instances that are misconfigured; disabled and empty create nothing
	counts := func(vulns []model.Vulnerability) map[string]int {
		out := map[string]int{}
		for i := range vulns {
			out[vulns[i].ResourceName]++
		}
		return out
	}
	want := map[string]int{"plain": 1, "counted": 1, "keyed": 1, "listed": 1, "constant": 1}
	require.Equal(t, want, counts(flat), "flat")

	// A module call reports each instance, so two instances that do not
	// differ report twice at the same place; a plain file reports it once.
	want["constant"] = 2
	require.Equal(t, want, counts(module), "module")
	for _, finding := range module {
		require.NotNil(t, finding.ModuleAttribution, "expanded findings retain module provenance")
	}
}

func TestInspectDynamicInstanceBindingsFlatAndModule(t *testing.T) {
	configs := map[string]string{
		"main.tf": `resource "aws_security_group" "sg" {
  count = 2
  dynamic "ingress" {
    for_each = [count.index]
    iterator = port
    content {
      from_port = port.value
    }
  }
}

`,
		"main.tf.json": `{
  "resource": {"aws_security_group": {"sg": {
    "count": 2,
    "dynamic": {"ingress": [{
      "for_each": "${[count.index]}", "iterator": "port",
      "content": {
        "from_port": "${port.value}"
      }
    }]}
  }}}
}`,
	}
	rule := `package datadog
ingress_port(group) := group.ingress.from_port
ingress_port(group) := group.ingress[0].from_port
DatadogPolicy contains result if {
  some i
  ingress_port(input.document[i].resource.aws_security_group.sg) == 1
  result := {"documentId": input.document[i].id, "resourceType": "aws_security_group", "resourceName": "sg",
    "searchKey": "aws_security_group[sg].ingress.from_port"}
}`
	for name, source := range configs {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			modulePath := filepath.Join(root, "module", name)
			require.NoError(t, os.MkdirAll(filepath.Dir(modulePath), 0o755))
			require.NoError(t, os.WriteFile(modulePath, []byte(source), 0o600))
			inspect := func(files model.FileMetadatas) []model.Vulnerability {
				ins := newTestInspector(t, inspectorOpts{
					queries: []model.QueryMetadata{{Query: "dynamic", Content: rule, InputData: "{}", Platform: "terraform",
						Metadata: map[string]interface{}{"id": "dynamic"}, Aggregation: 1}},
					repoPath: root, vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator(),
				})
				got, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
				require.NoError(t, err)
				require.Empty(t, ins.GetFailedQueries())
				return got
			}
			flat := inspect(parseTerraform(t, modulePath))
			require.Len(t, flat, 1)
			line := strings.Count(source[:strings.Index(source, "from_port")], "\n") + 1
			require.Equal(t, line, flat[0].Line)

			caller := filepath.Join(root, "main.tf")
			require.NoError(t, os.WriteFile(caller, []byte("module \"m\" { source = \"./module\" }"), 0o600))
			files := append(parseTerraform(t, caller), parseTerraform(t, modulePath)...)
			instantiated := inspect(files)
			require.Len(t, instantiated, 1, "defining-file layers must be suppressed")
			require.Equal(t, line, instantiated[0].Line)
			require.NotNil(t, instantiated[0].ModuleAttribution)
			require.Equal(t, "module/"+name, instantiated[0].ModuleAttribution.ModuleCodeLocation.Filename)
			require.Equal(t, line, instantiated[0].ModuleAttribution.ModuleCodeLocation.LineStart)
		})
	}
}

func TestInspectTruncatedModuleExpansionReplacesDefiningLayers(t *testing.T) {
	for _, name := range []string{"main.tf", "main.tf.json"} {
		t.Run(name, func(t *testing.T) { truncatedModuleExpansion(t, name) })
	}
}

func truncatedModuleExpansion(t *testing.T, name string) {
	t.Helper()
	for _, acl := range []string{"private", "public-read"} {
		t.Run(acl, func(t *testing.T) {
			root := t.TempDir()
			modulePath := filepath.Join(root, "module", name)
			require.NoError(t, os.MkdirAll(filepath.Dir(modulePath), 0o755))
			source := `
variable "acl" { default = "public-read" }
resource "aws_s3_bucket" "b" {
  count = 55
  bucket = "i-${count.index}"
  acl = count.index == 1 ? var.acl : "private"
}
`
			if strings.HasSuffix(name, ".json") {
				source = `{
 "variable": {"acl": {"default": "public-read"}},
 "resource": {"aws_s3_bucket": {"b": {
  "count": 55, "bucket": "i-${count.index}",
  "acl": "${count.index == 1 ? var.acl : \"private\"}"
 }}}
}`
			}
			require.NoError(t, os.WriteFile(modulePath, []byte(source), 0o600))
			caller := filepath.Join(root, "main.tf")
			require.NoError(t, os.WriteFile(caller, []byte(`module "m" {
  source = "./module"
  acl = "`+acl+`"
}`), 0o600))
			files := append(parseTerraform(t, caller), parseTerraform(t, modulePath)...)
			got := expansionFindings(t, root, files)
			if acl == "private" {
				require.Empty(t, got, "defining-file defaults must not create a false positive")
			} else {
				require.Len(t, got, 1, "concrete instances must not repeat in defining-file layers")
				require.NotNil(t, got[0].ModuleAttribution)
			}
			// The omitted tail still has a module-scoped, as-written scan view.
			rule := strings.ReplaceAll(aclRule, `bucket.acl == "public-read"`, `bucket.bucket == "i-${count.index}"`)
			ins := newTestInspector(t, inspectorOpts{
				queries: []model.QueryMetadata{{Query: "tail", Content: rule, InputData: "{}", Platform: "terraform",
					Metadata: map[string]interface{}{"id": "tail"}, Aggregation: 1}},
				repoPath: root, vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator(),
			})
			files = append(parseTerraform(t, caller), parseTerraform(t, modulePath)...)
			tail, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
			require.NoError(t, err)
			require.Len(t, tail, 1)
			require.NotNil(t, tail[0].ModuleAttribution)
		})
	}
}
