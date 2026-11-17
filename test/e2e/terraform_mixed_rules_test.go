/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const mixedLegacyRule = `package datadog

import rego.v1

DatadogPolicy contains result if {
	doc := input.document[i]
	some name, _ in doc.resource.aws_s3_bucket
	result := {
		"documentId": doc.id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s]", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "x",
		"keyActualValue": "y",
	}
}
`

const mixedLegacyMeta = `{
  "id": "mixed-legacy-bucket",
  "queryName": "Mixed legacy bucket",
  "severity": "LOW",
  "category": "Best Practices",
  "descriptionText": "x",
  "descriptionUrl": "https://example.com",
  "platform": "Terraform",
  "descriptionID": "-legacy",
  "cloudProvider": "aws"
}`

// copyTree copies the tree at src to dst.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	require.NoError(t, filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o600)
	}))
}

// mixedRules is a rules directory with the contract companion rule, a legacy
// bucket rule, or both.
func mixedRules(t *testing.T, contract, legacy bool) string {
	t.Helper()
	dir := t.TempDir()
	src := mustAbs(t, filepath.Join("testdata", "terraform_rules"))
	copyTree(t, filepath.Join(src, "libraries"), filepath.Join(dir, "libraries"))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "terraform"), 0o755))
	if contract {
		copyTree(t, filepath.Join(src, "terraform", "companion_not_enabled"), filepath.Join(dir, "terraform", "companion_not_enabled"))
	}
	if legacy {
		l := filepath.Join(dir, "terraform", "legacy_bucket")
		require.NoError(t, os.MkdirAll(l, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(l, "query.rego"), []byte(mixedLegacyRule), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(l, "metadata.json"), []byte(mixedLegacyMeta), 0o600))
	}
	return dir
}

func TestTerraformContractAndLegacyRulesInOneScan(t *testing.T) {
	for _, fixture := range []struct {
		name  string
		plans bool
	}{{"plan", true}, {"cross-root", false}} {
		t.Run(fixture.name, func(t *testing.T) {
			path := filepath.Join("fixtures", fixture.name)
			scan := func(c, l bool) (contract, legacy []string) {
				out := t.TempDir()
				runTerraformScanTo(t, path, mixedRules(t, c, l), out, fixture.plans)
				return anchoredLines(t, out, "Bucket without enabled versioning companion"),
					anchoredLines(t, out, "Mixed legacy bucket")
			}
			cOnly, _ := scan(true, false)
			_, lOnly := scan(false, true)
			cBoth, lBoth := scan(true, true)
			require.Equal(t, cOnly, cBoth)
			require.Equal(t, lOnly, lBoth)
			require.NotEmpty(t, lOnly)
		})
	}
}
