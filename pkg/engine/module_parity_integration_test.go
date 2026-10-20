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
	"sort"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

const wildcardPolicyRule = `package datadog

DatadogPolicy contains result if {
	some name, i
	queue_policy := input.document[i].resource.aws_sqs_queue_policy[name]
	policy := json.unmarshal(queue_policy.policy)
	some statement in policy.Statement
	wildcard(statement)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_sqs_queue_policy",
		"resourceName": name,
		"searchKey": sprintf("aws_sqs_queue_policy[%s].policy", [name]),
	}
}

wildcard(statement) if statement.Principal == "*"

wildcard(statement) if "*" in statement.Principals.AWS
`

const amiOwnerRule = `package datadog

DatadogPolicy contains result if {
	some name, i
	ami := input.document[i].data.aws_ami[name]
	not ami.owners

	result := {
		"documentId": input.document[i].id,
		"resourceType": "data.aws_ami",
		"resourceName": name,
		"searchKey": sprintf("data.aws_ami[%s]", [name]),
	}
}
`

const publicKMSRule = `package datadog

DatadogPolicy contains result if {
	some name, i
	kms := input.document[i].resource.google_kms_crypto_key_iam_policy[name]
	policy := json.unmarshal(kms.policy_data)
	some binding in policy.bindings
	"allUsers" in binding.members

	result := {
		"documentId": input.document[i].id,
		"resourceType": "google_kms_crypto_key_iam_policy",
		"resourceName": name,
		"searchKey": sprintf("google_kms_crypto_key_iam_policy[%s].policy_data", [name]),
	}
}
`

const parityConfig = `
resource "aws_sqs_queue" "q" {
  name = "q"
}

resource "aws_sqs_queue_policy" "inline" {
  queue_url = aws_sqs_queue.q.id
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = PRINCIPAL
      Action    = "sqs:*"
      Resource  = aws_sqs_queue.q.arn
    }]
  })
}

data "aws_iam_policy_document" "doc" {
  statement {
    actions   = ["sqs:*"]
    resources = [aws_sqs_queue.q.arn]
    principals {
      type        = "AWS"
      identifiers = [PRINCIPAL]
    }
  }
}

resource "aws_sqs_queue_policy" "from_data" {
  queue_url = aws_sqs_queue.q.id
  policy    = data.aws_iam_policy_document.doc.json
}

data "aws_ami" "ubuntu" {
  most_recent = true
}

data "google_iam_policy" "kms" {
  binding {
    role    = "roles/cloudkms.cryptoKeyDecrypter"
    members = [PRINCIPAL == "*" ? "allUsers" : PRINCIPAL]
  }
}

resource "google_kms_crypto_key_iam_policy" "key" {
  crypto_key_id = "k"
  policy_data   = data.google_iam_policy.kms.policy_data
}
`

func parityFindings(t *testing.T, root string, files model.FileMetadatas) []model.Vulnerability {
	t.Helper()
	var queries []model.QueryMetadata
	for id, rule := range map[string]string{
		"wildcard-policy": wildcardPolicyRule, "ami-owner": amiOwnerRule, "public-kms": publicKMSRule,
	} {
		queries = append(queries, model.QueryMetadata{
			Query: id, Content: rule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": id}, Aggregation: 1,
		})
	}
	ins := newTestInspector(t, inspectorOpts{
		queries:       queries,
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	return vulns
}

func findingKeys(vulns []model.Vulnerability) []string {
	keys := make([]string, 0, len(vulns))
	for i := range vulns {
		keys = append(keys, vulns[i].QueryID+" "+vulns[i].ResourceType+" "+vulns[i].ResourceName)
	}
	sort.Strings(keys)
	return keys
}

// A value passed into a module must be checked exactly as the same value
// written in place: policies built around computed attributes, policies built
// by data sources, and data blocks all included.
func TestInspect_ModuleFindingsMatchFlatConfiguration(t *testing.T) {
	root := t.TempDir()

	flatPath := filepath.Join(root, "flat", "main.tf")
	require.NoError(t, os.MkdirAll(filepath.Dir(flatPath), 0o755))
	require.NoError(t, os.WriteFile(flatPath, []byte(strings.ReplaceAll(parityConfig, "PRINCIPAL", `"*"`)), 0o644))
	flat := parityFindings(t, filepath.Dir(flatPath), parseTerraform(t, flatPath))

	rootPath := filepath.Join(root, "stack", "main.tf")
	modPath := filepath.Join(root, "modules", "queue", "main.tf")
	require.NoError(t, os.MkdirAll(filepath.Dir(rootPath), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Dir(modPath), 0o755))
	require.NoError(t, os.WriteFile(rootPath, []byte(`
module "queue" {
  source    = "../modules/queue"
  principal = "*"
}
`), 0o644))
	require.NoError(t, os.WriteFile(modPath, []byte(
		"variable \"principal\" {}\n"+strings.ReplaceAll(parityConfig, "PRINCIPAL", "var.principal")), 0o644))
	var files model.FileMetadatas
	files = append(files, parseTerraform(t, rootPath)...)
	files = append(files, parseTerraform(t, modPath)...)
	module := parityFindings(t, root, files)

	want := []string{
		"ami-owner data.aws_ami ubuntu",
		"public-kms google_kms_crypto_key_iam_policy key",
		"wildcard-policy aws_sqs_queue_policy from_data",
		"wildcard-policy aws_sqs_queue_policy inline",
	}
	require.Equal(t, want, findingKeys(flat))
	require.Equal(t, want, findingKeys(module))
	for i := range module {
		v := &module[i]
		require.Equal(t, modPath, v.FileName, v.QueryID)
		require.NotNil(t, v.ModuleAttribution, v.QueryID)
		require.Equal(t, "stack/main.tf", v.ModuleAttribution.CallSite.Filename, v.QueryID)
	}
}
