package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

const ephemeralRule = `package datadog

DatadogPolicy contains result if {
	some name, i
	secret := input.document[i].ephemeral.aws_secretsmanager_secret[name]
	secret.name

	result := {
		"documentId": input.document[i].id,
		"resourceType": "ephemeral.aws_secretsmanager_secret",
		"resourceName": name,
		"searchKey": sprintf("ephemeral.aws_secretsmanager_secret[%s].name", [name]),
	}
}
`

// Ephemeral resource blocks are expanded like resources: one finding per
// instance, each addressed with its instance suffix, and a root-declared
// ephemeral block resolves against the file's declared blocks.
func TestInspect_EphemeralInstancesAreAddressed(t *testing.T) {
	root := t.TempDir()
	rootPath := filepath.Join(root, "main.tf")
	require.NoError(t, os.WriteFile(rootPath, []byte(`
ephemeral "aws_secretsmanager_secret" "login" {
  for_each = toset(["a", "b"])
  name     = each.key
}
`), 0o644))

	files := parseTerraform(t, rootPath)
	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "ephemeral_rule", Content: ephemeralRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "eph-rule", "platform": "Terraform"}, Aggregation: 1,
		}},
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 2, "each ephemeral instance is its own finding")
	ids := []string{vulns[0].ResourceID, vulns[1].ResourceID}
	require.ElementsMatch(t, []string{
		`ephemeral.aws_secretsmanager_secret.login["a"]`,
		`ephemeral.aws_secretsmanager_secret.login["b"]`,
	}, ids)
	require.Equal(t, ".", vulns[0].RootModule, "the file sits at the repository root")
}
