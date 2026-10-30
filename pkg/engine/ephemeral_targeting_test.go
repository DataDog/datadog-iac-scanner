package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/stretchr/testify/require"
)

// Ephemeral declarations count as targeted resources. The targets come from
// the real collector over a mixed ruleset — an ephemeral rule and an
// unrelated bucket rule — so the ephemeral type is picked up through
// ephemeralFieldPattern while targets stay non-nil, and a keyed module call
// is instantiated like a resource (K9CODESEC-7158).
func TestResolveModuleDocuments_EphemeralTargeted(t *testing.T) {
	root := t.TempDir()
	stackDir := filepath.Join(root, "stack")
	modDir := filepath.Join(root, "modules", "secrets")
	require.NoError(t, os.MkdirAll(stackDir, 0o755))
	require.NoError(t, os.MkdirAll(modDir, 0o755))
	rootPath := filepath.Join(stackDir, "main.tf")
	require.NoError(t, os.WriteFile(rootPath, []byte(`
module "secrets" {
  source = "../modules/secrets"
  names  = ["a", "b"]
}
`), 0o644))
	modPath := filepath.Join(modDir, "main.tf")
	require.NoError(t, os.WriteFile(modPath, []byte(`
variable "names" {
  type = list(string)
}

ephemeral "aws_secretsmanager_secret" "login" {
  for_each = toset(var.names)
  name     = each.key
}
`), 0o644))

	var files model.FileMetadatas
	files = append(files, parseTerraform(t, rootPath)...)
	files = append(files, parseTerraform(t, modPath)...)

	// The mixed ruleset: an ephemeral rule (reporting the namespaced type,
	// like the rules repo does) and an unrelated bucket rule. The collector
	// must pick the ephemeral type out of the ephemeral rule.
	queries := []model.QueryMetadata{
		{
			Query: "eph_rule", Content: `package datadog

DatadogPolicy contains result if {
	secret := input.document[i].ephemeral.aws_secretsmanager_secret[name]
	secret.name

	result := {
		"documentId": input.document[i].id,
		"resourceType": "ephemeral.aws_secretsmanager_secret",
		"resourceName": name,
		"searchKey": sprintf("ephemeral.aws_secretsmanager_secret[%s].name", [name]),
	}
}
`, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "eph-rule", "platform": "Terraform"}, Aggregation: 1,
		},
		{
			Query: "bucket_rule", Content: `package datadog

DatadogPolicy contains result if {
	bucket := input.document[i].resource.aws_s3_bucket[name]
	bucket.acl

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": "aws_s3_bucket[name].acl",
	}
}
`, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "bucket-rule", "platform": "Terraform"}, Aggregation: 1,
		},
	}
	targets := ruleTargetedResourceTypes(queries)
	require.NotNil(t, targets, "the mixed ruleset collects targets")
	require.True(t, targets.matches("ephemeral.aws_secretsmanager_secret"),
		"the collector picks the namespaced ephemeral type out of the ephemeral rule")
	require.True(t, targets.matches("aws_s3_bucket"))

	res := resolveModuleDocuments(
		context.Background(), files, root, relDirForTest(root), nil, targets, nil, nil, nil, nil)
	require.True(t, res.ok)
	require.NotEmpty(t, res.docs, "the keyed ephemeral block must be instantiated")
	require.NotEmpty(t, res.suppressed, "the module body's ephemeral block is instantiated")

	// The synthetic documents' scopes carry the per-instance keys: one
	// document per keyed instance, each addressing its own instance under the
	// call's module path.
	seen := map[string]bool{}
	for _, f := range res.syntheticFiles {
		scope := f.TerraformScope
		require.NotNil(t, scope)
		block := model.TerraformBlock{Kind: "ephemeral", Type: "aws_secretsmanager_secret", Name: "login"}
		suffix, ok := scope.Instances[block]
		require.True(t, ok, "the ephemeral instance key must be on the synthetic scope: %v", scope.Instances)
		resourceID := address.Instance(scope.ModuleAddress, block, suffix)
		seen[resourceID] = true
	}
	require.ElementsMatch(t, []string{
		`module.secrets.ephemeral.aws_secretsmanager_secret.login["a"]`,
		`module.secrets.ephemeral.aws_secretsmanager_secret.login["b"]`,
	}, keysOf(seen))
}

// The same input with only the unrelated bucket rule: nothing ephemeral is
// targeted, so nothing is instantiated and nothing is suppressed — the
// blocks stay scanned where they are written.
func TestResolveModuleDocuments_EphemeralNotTargetedStaysAsWritten(t *testing.T) {
	root := t.TempDir()
	stackDir := filepath.Join(root, "stack")
	modDir := filepath.Join(root, "modules", "secrets")
	require.NoError(t, os.MkdirAll(stackDir, 0o755))
	require.NoError(t, os.MkdirAll(modDir, 0o755))
	rootPath := filepath.Join(stackDir, "main.tf")
	require.NoError(t, os.WriteFile(rootPath, []byte(`
module "secrets" {
  source = "../modules/secrets"
  names  = ["a"]
}
`), 0o644))
	modPath := filepath.Join(modDir, "main.tf")
	require.NoError(t, os.WriteFile(modPath, []byte(`
variable "names" {
  type = list(string)
}

ephemeral "aws_secretsmanager_secret" "login" {
  for_each = toset(var.names)
  name     = each.key
}
`), 0o644))

	var files model.FileMetadatas
	files = append(files, parseTerraform(t, rootPath)...)
	files = append(files, parseTerraform(t, modPath)...)

	targets := ruleTargetedResourceTypes([]model.QueryMetadata{{
		Query: "bucket_rule", Content: `package datadog

DatadogPolicy contains result if {
	bucket := input.document[i].resource.aws_s3_bucket[name]
	bucket.acl

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": "aws_s3_bucket[name].acl",
	}
}
`, InputData: "{}", Platform: "terraform",
		Metadata: map[string]interface{}{"id": "bucket-rule", "platform": "Terraform"}, Aggregation: 1,
	}})
	require.False(t, declaresTargetedResource(files, targets),
		"an ephemeral-only file declares nothing the bucket rule matches")

	res := resolveModuleDocuments(
		context.Background(), files, root, relDirForTest(root), nil, targets, nil, nil, nil, nil)
	// Nothing targeted: nothing instantiated, nothing suppressed, exactly the
	// outcome the caller (instantiateLocalModules) applies.
	require.Empty(t, res.docs)
	require.Empty(t, res.suppressed)
}

// A managed resource and an ephemeral block sharing type and name are two
// different blocks: the evaluator carries the kind from HCL, so their
// expansions and references never merge (K9CODESEC-7158).
func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestInspect_ManagedAndEphemeralSameNameStayApart(t *testing.T) {
	root := t.TempDir()
	rootPath := filepath.Join(root, "main.tf")
	require.NoError(t, os.WriteFile(rootPath, []byte(`
resource "random_password" "x" {
  for_each = toset(["m"])
  result   = "managed"
}

ephemeral "random_password" "x" {
  for_each = toset(["e1", "e2"])
  result   = each.key
}
`), 0o644))

	ephRule := `package datadog

DatadogPolicy contains result if {
	some name, i
	secret := input.document[i].ephemeral.random_password[name]
	secret.result

	result := {
		"documentId": input.document[i].id,
		"resourceType": "ephemeral.random_password",
		"resourceName": name,
		"searchKey": sprintf("ephemeral.random_password[%s].result", [name]),
	}
}
`
	files := parseTerraform(t, rootPath)
	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "eph_rule", Content: ephRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "eph-rule", "platform": "Terraform"}, Aggregation: 1,
		}},
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 2, "only the ephemeral rule's instances are reported, both addressed")
	ids := []string{vulns[0].ResourceID, vulns[1].ResourceID}
	require.ElementsMatch(t, []string{
		`ephemeral.random_password.x["e1"]`,
		`ephemeral.random_password.x["e2"]`,
	}, ids, "the managed random_password.x must never answer for the ephemeral one")
}

// A JSON-configured module's ephemeral instances are addressed under the
// call's module path like HCL ones: the JSON config schema must know the
// ephemeral block type, or the caller's instances are lost
// (K9CODESEC-7158).
func TestInspect_JSONModuleEphemeralInstancesAddressed(t *testing.T) {
	root := t.TempDir()
	stackDir := filepath.Join(root, "stack")
	modDir := filepath.Join(root, "modules", "secrets")
	require.NoError(t, os.MkdirAll(stackDir, 0o755))
	require.NoError(t, os.MkdirAll(modDir, 0o755))
	rootPath := filepath.Join(stackDir, "main.tf")
	require.NoError(t, os.WriteFile(rootPath, []byte(`
module "secrets" {
  source = "../modules/secrets"
}
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(modDir, "main.tf.json"), []byte(`{
  "ephemeral": {
    "aws_secretsmanager_secret": {
      "login": {
        "for_each": {"a": {}, "b": {}},
        "name": "secret-${each.key}"
      }
    }
  }
}
`), 0o644))

	var files model.FileMetadatas
	files = append(files, parseTerraform(t, rootPath)...)
	files = append(files, parseTerraform(t, filepath.Join(modDir, "main.tf.json"))...)

	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "eph_rule", Content: `package datadog

DatadogPolicy contains result if {
	secret := input.document[i].ephemeral.aws_secretsmanager_secret[name]
	secret.name

	result := {
		"documentId": input.document[i].id,
		"resourceType": "ephemeral.aws_secretsmanager_secret",
		"resourceName": name,
		"searchKey": sprintf("ephemeral.aws_secretsmanager_secret[%s].name", [name]),
	}
}
`, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "eph-rule", "platform": "Terraform"}, Aggregation: 1,
		}},
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 2, "both JSON ephemeral instances are reported")
	ids := []string{vulns[0].ResourceID, vulns[1].ResourceID}
	require.ElementsMatch(t, []string{
		`module.secrets.ephemeral.aws_secretsmanager_secret.login["a"]`,
		`module.secrets.ephemeral.aws_secretsmanager_secret.login["b"]`,
	}, ids)
}
