package ruletest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func names(files []File) []string {
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = f.Name
	}
	return out
}

func TestFixtureRoots(t *testing.T) {
	files := []File{
		{Name: "positive1.tf"},
		{Name: "cert.pem"},
		{Name: "negative.tf"},
		{Name: "stack/positive_a.tf"},
		{Name: "positive2.tf"},
		{Name: "stack/modules/m/positive_child.tf"},
		{Name: "stack/negative_b.tf"},
		{Name: "other/negative_x.tf"},
	}

	positives := fixtureRoots(files, positivePrefix, false)
	require.Len(t, positives, 3)
	assert.Equal(t, []string{"cert.pem", "positive1.tf"}, names(positives[0].files))
	assert.Equal(t, []string{"positive1.tf"}, positives[0].parse)
	assert.Equal(t, []string{"cert.pem", "stack/positive_a.tf", "stack/modules/m/positive_child.tf", "stack/negative_b.tf"},
		names(positives[1].files))
	assert.Equal(t, []string{"stack/positive_a.tf", "stack/modules/m/positive_child.tf"}, positives[1].parse)
	assert.Equal(t, []string{"cert.pem", "positive2.tf"}, names(positives[2].files))

	negatives := fixtureRoots(files, negativePrefix, false)
	require.Len(t, negatives, 3)
	assert.Equal(t, []string{"negative.tf"}, negatives[0].parse)
	assert.Equal(t, []string{"stack/negative_b.tf"}, negatives[1].parse)
	assert.Equal(t, []string{"cert.pem", "other/negative_x.tf"}, names(negatives[2].files))

	legacy := fixtureRoots(files, negativePrefix, true)
	require.Len(t, legacy, 1)
	assert.Equal(t, files, legacy[0].files)
	assert.Equal(t, []string{"negative.tf", "stack/negative_b.tf", "other/negative_x.tf"}, legacy[0].parse)
	assert.Empty(t, fixtureRoots([]File{{Name: "cert.pem"}}, positivePrefix, true))
}

func TestRootWriteRejectsEscapingPaths(t *testing.T) {
	for _, name := range []string{"../outside.tf", "a/../../outside.tf"} {
		_, err := root{files: []File{{Name: name}}}.write(t.TempDir())
		assert.Error(t, err, name)
	}
}

func TestValidateResult(t *testing.T) {
	legacy := map[string]any{"documentId": "d", "searchKey": "k", "resourceType": "t", "resourceName": "n"}
	assert.Empty(t, validateResult(legacy, "Terraform", "r", true), "deprecated fields are not required")

	assert.Equal(t, []string{
		`Result missing required field "searchKey"`,
		`Result missing required field "resourceName" for platform "terraform" in rule r`,
	}, validateResult(map[string]any{"documentId": "d", "resourceType": "t"}, "Terraform", "r", true))

	assert.Empty(t, validateResult(map[string]any{"_dd_id": "root/aws_s3_bucket.b", "path": []any{}}, "Terraform", "r", true))
	for _, block := range []any{"", 3, nil} {
		assert.Equal(t, []string{`Result field "_dd_id" must be a non-empty string`},
			validateResult(map[string]any{"_dd_id": block, "path": []any{}}, "Terraform", "r", true))
	}

	assert.Equal(t, []string{"Result has remediation/remediationType only on one side; both must be set together"},
		validateResult(map[string]any{"_dd_id": "b", "path": []any{}, "remediation": "x"}, "Terraform", "r", true))
}

func TestValidateBlockResult(t *testing.T) {
	valid := map[string]any{
		"_dd_id":   "b",
		"path":     []any{"ingress", json.Number("0"), "cidr_blocks"},
		"key":      json.Number("22"),
		"evidence": []any{[]any{"c", []any{"bucket"}}},
	}
	assert.Empty(t, validateResult(valid, "Terraform", "r", true))

	assert.Equal(t, []string{
		`Result missing required field "path"`,
		`Result field "resourceType" is derived from "_dd_id" and must not be set`,
	}, validateResult(map[string]any{"_dd_id": "b", "resourceType": "t"}, "Terraform", "r", true))

	assert.Equal(t, []string{
		`Result field "path" holds -1, not a list index`,
		`Result field "key" must be a string, number or boolean`,
		`Result field "evidence" item 0 must be a [block id, path] pair`,
		`Result field "evidence" item 1 path must be an array`,
	}, validateResult(map[string]any{
		"_dd_id":   "b",
		"path":     []any{json.Number("-1")},
		"key":      []any{"a"},
		"evidence": []any{"c", []any{"c", "bucket"}},
	}, "Terraform", "r", true))
}

func TestCompareFindings(t *testing.T) {
	a := Finding{QueryName: "q", Severity: "HIGH", Line: 1, FileName: "a.tf"}
	b := Finding{QueryName: "q", Severity: "HIGH", Line: 1, FileName: "b.tf"}
	wildcard := Finding{QueryName: "q", Severity: "HIGH", Line: 1}

	assert.Empty(t, compareFindings([]Finding{wildcard, a}, []Finding{a, b}))
	assert.Equal(t, []Mismatch{
		{Kind: MissingFinding, Finding: b},
		{Kind: UnexpectedFinding, Finding: a},
	}, compareFindings([]Finding{b}, []Finding{a}))
}

func TestRuleMatch(t *testing.T) {
	r := &Rule{ID: "terraform-x", LegacyID: "legacy", Platform: "Terraform"}
	assert.True(t, r.Match(nil, nil))
	assert.True(t, r.Match([]string{"terraform"}, []string{"legacy"}))
	assert.False(t, r.Match([]string{"Dockerfile"}, nil))
	assert.False(t, r.Match(nil, []string{"other"}))
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
}

func metadata(t *testing.T, id, name, platform, severity string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"id": id, "queryName": name, "platform": platform, "severity": severity, "category": "Best Practices",
	})
	require.NoError(t, err)
	return string(b)
}

const bucketRule = `package datadog

import rego.v1

DatadogPolicy contains result if {
	some doc in input.document
	some name, _ in doc.resource.aws_s3_bucket
	not has_versioning
	result := {
		"documentId": doc.id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s]", [name]),
	}
}

has_versioning if {
	some doc in input.document
	doc.resource.aws_s3_bucket_versioning
}
`

const addRule = `package datadog

import rego.v1

DatadogPolicy contains result if {
	some doc in input.document
	some name, commands in doc.command
	some c in commands
	c.Cmd == "add"
	not input.arguments.allow_add
	result := {
		"documentId": doc.id,
		"searchKey": sprintf("FROM={{%s}}.{{%s}}", [name, c.Original]),
	}
}
`

const bucket = "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"b\"\n}\n"
const versioning = "resource \"aws_s3_bucket_versioning\" \"v\" {\n  bucket = \"b\"\n}\n"

const publicBucketRule = `package datadog

import rego.v1

import data.generic.common as common
import data.generic.terraform as tf

DatadogPolicy contains result if {
	some b in tf.blocks("aws_s3_bucket")
	b.acl == "public-read"
	result := common.finding(b, ["acl"], {})
}
`

const contractTerraformLibrary = `package generic.terraform

import rego.v1

blocks(type) := object.get(input._dd, ["blocks", "resource", type], [])
`

const contractCommonLibrary = `package generic.common

import rego.v1

finding(subject, path, details) := object.union(details, {"_dd_id": subject._dd_meta.id, "path": path})
`

func testAssets(t *testing.T) string {
	t.Helper()
	assets := t.TempDir()
	tfRule := "queries/terraform/aws/bucket_without_versioning/"
	contractRule := "queries/terraform/aws/public_bucket/"
	dockerRule := "queries/dockerfile/add_command/"
	writeFiles(t, assets, map[string]string{
		"libraries/common.rego":     contractCommonLibrary,
		"libraries/common.json":     "{}",
		"libraries/terraform.rego":  contractTerraformLibrary,
		"libraries/dockerfile.rego": "package generic.dockerfile\n",

		tfRule + "metadata.json": metadata(t, "terraform-aws-bucket-without-versioning", "Bucket without versioning", "Terraform", "HIGH"),
		tfRule + "query.rego":    bucketRule,
		// Top-level files are separate roots: the versioning resource of
		// positive2.tf does not clear the bucket of positive1.tf, and the
		// duplicate address in negative.tf does not collide.
		tfRule + "test/positive1.tf": bucket,
		tfRule + "test/positive2.tf": versioning,
		tfRule + "test/negative.tf":  bucket + versioning,
		// A subdirectory is one root.
		tfRule + "test/stack/negative_bucket.tf":     bucket,
		tfRule + "test/stack/negative_versioning.tf": versioning,
		tfRule + "test/positive_expected_result.json": `[
  {"queryName": "Bucket without versioning", "severity": "HIGH", "line": 1, "fileName": "positive1.tf"}
]`,

		// Contract rule: count instances and a module call site.
		contractRule + "metadata.json": metadata(t, "terraform-aws-public-bucket", "Public bucket", "Terraform", "HIGH"),
		contractRule + "query.rego":    publicBucketRule,
		contractRule + "test/positive.tf": `resource "aws_s3_bucket" "b" {
  count  = 60
  bucket = "b-${count.index}"
  acl    = count.index == 59 ? "public-read" : "private"
}
`,
		contractRule + "test/stack/positive_main.tf": "module \"m\" {\n  source = \"./m\"\n}\n",
		contractRule + "test/stack/m/positive_m.tf":  "resource \"aws_s3_bucket\" \"b\" {\n  acl = \"public-read\"\n}\n",
		contractRule + "test/negative.tf":            "resource \"aws_s3_bucket\" \"b\" {\n  acl = \"private\"\n}\n",
		contractRule + "test/positive_expected_result.json": `[
  {"queryName": "Public bucket", "severity": "HIGH", "line": 4, "fileName": "positive.tf"},
  {"queryName": "Public bucket", "severity": "HIGH", "line": 2, "fileName": "positive_main.tf"}
]`,

		dockerRule + "metadata.json":                      metadata(t, "dockerfile-add-command", "ADD command", "Dockerfile", "LOW"),
		dockerRule + "query.rego":                         addRule,
		dockerRule + "test/positive.dockerfile":           "FROM alpine:3.20\nADD app /app\n",
		dockerRule + "test/negative.dockerfile":           "FROM alpine:3.20\nCOPY app /app\n",
		dockerRule + "test/positive_expected_result.json": `[{"queryName": "ADD command", "severity": "LOW", "line": 2}]`,
		dockerRule + "test_arguments/positive.dockerfile": "FROM alpine:3.20\nADD app /app\n",
		dockerRule + "test_arguments/arguments_expected_result.json": `[
  {"arguments": null, "findings": [{"queryName": "ADD command", "severity": "LOW", "line": 2}]},
  {"arguments": {"allow_add": true}, "findings": []}
]`,

		"queries/dockerfile/untested/metadata.json":         metadata(t, "dockerfile-untested", "Untested", "Dockerfile", "LOW"),
		"queries/dockerfile/untested/query.rego":            addRule,
		"queries/dockerfile/trace/metadata.json":            metadata(t, "dockerfile-trace", "Trace", "Dockerfile", "TRACE"),
		"queries/dockerfile/trace/query.rego":               addRule,
		"queries/dockerfile/trace/test/positive.dockerfile": "FROM alpine:3.20\n",
	})
	return assets
}

func TestLoadDirAndRun(t *testing.T) {
	ctx := context.Background()
	suite, err := LoadDir(ctx, testAssets(t))
	require.NoError(t, err)
	require.Len(t, suite.Rules, 3, "rules without tests and TRACE rules are skipped")

	byID := map[string]*Rule{}
	for _, rule := range suite.Rules {
		byID[rule.ID] = rule
	}
	docker := byID["dockerfile-add-command"]
	tf := byID["terraform-aws-bucket-without-versioning"]
	contract := byID["terraform-aws-public-bucket"]
	require.NotNil(t, docker)
	require.NotNil(t, tf)
	require.NotNil(t, contract)
	assert.Equal(t, "Dockerfile", docker.Platform)
	require.NotNil(t, docker.ArgumentTests)
	assert.Len(t, docker.ArgumentTests.Cases, 2)
	assert.Len(t, tf.Tests.Files, 5)

	for _, rule := range suite.Rules {
		res, err := suite.Run(ctx, rule, Options{RequireFixtures: true})
		require.NoError(t, err)
		assert.Empty(t, res.Mismatches, rule.ID)
	}

	// With one root, positive2.tf clears the finding of positive1.tf.
	res, err := suite.Run(ctx, tf, Options{LegacyRoots: true})
	require.NoError(t, err)
	assert.Equal(t, []Mismatch{{Kind: MissingFinding, Finding: tf.Tests.Expected[0]}}, res.Mismatches)
}

func TestRunReportsMismatches(t *testing.T) {
	ctx := context.Background()
	suite, err := LoadDir(ctx, testAssets(t))
	require.NoError(t, err)
	docker := suite.Rules[0]
	docker.Tests.Expected[0].Line = 3
	docker.ArgumentTests.Cases[1].Arguments = nil

	res, err := suite.Run(ctx, docker, Options{})
	require.NoError(t, err)
	got := Finding{QueryName: "ADD command", Severity: "LOW", Line: 2, FileName: "positive.dockerfile"}
	assert.Equal(t, []Mismatch{
		{Kind: MissingFinding, Finding: Finding{QueryName: "ADD command", Severity: "LOW", Line: 3}},
		{Kind: UnexpectedFinding, Finding: got},
		{Kind: UnexpectedFinding, Case: 2, Finding: got},
	}, res.Mismatches)
}

func TestRunReportsQueryErrorOncePerPolarity(t *testing.T) {
	ctx := context.Background()
	suite, err := LoadDir(ctx, testAssets(t))
	require.NoError(t, err)
	docker := suite.Rules[0]
	docker.Query.Content = "package datadog\n\nDatadogPolicy contains result if {\n\tresult := x\n}\n"
	docker.Tests.Files = append(docker.Tests.Files, File{Name: "positive2.dockerfile", Content: []byte("FROM alpine:3.20\n")})
	docker.Tests.Expected = nil
	docker.ArgumentTests = nil

	res, err := suite.Run(ctx, docker, Options{})
	require.NoError(t, err)
	require.Len(t, res.Mismatches, 2)
	for _, m := range res.Mismatches {
		assert.Equal(t, QueryFailed, m.Kind)
		assert.Contains(t, m.Message, "var x is unsafe")
	}
}

func TestSortErrorLines(t *testing.T) {
	assert.Equal(t, "2 errors occurred:\na\nb", sortErrorLines("2 errors occurred:\nb\na"))
	assert.Equal(t, "one error", sortErrorLines("one error"))
}

func TestRunReportsMissingFixtures(t *testing.T) {
	ctx := context.Background()
	suite, err := LoadDir(ctx, testAssets(t))
	require.NoError(t, err)
	docker := suite.Rules[0]
	docker.Tests.Files = docker.Tests.Files[:1]

	res, err := suite.Run(ctx, docker, Options{RequireFixtures: true})
	require.NoError(t, err)
	assert.Contains(t, res.Mismatches, Mismatch{Kind: MissingFixtures, Message: "No positive* sample files found"})
}

func TestLoadAPI(t *testing.T) {
	dir := t.TempDir()
	legacyID := "legacy-add"
	ruleset := datadog.Ruleset{ID: "default", Rules: []*datadog.Rule{
		{
			ID: "dockerfile-add-command", LegacyId: &legacyID, ShortDescription: "ADD command", Platform: "Dockerfile",
			Type: "rego", RegoQuery: []byte(addRule), Severity: "LOW", IsPublished: true,
			Tests: &datadog.RuleTests{
				Files: []datadog.TestFile{
					{FileName: "positive.dockerfile", Content: []byte("FROM alpine:3.20\nADD app /app\n")},
					{FileName: "negative.dockerfile", Content: []byte("FROM alpine:3.20\n")},
				},
				Expected: []datadog.TestFinding{{ShortDescription: "ADD command", Severity: "LOW", Line: 2}},
			},
		},
		{ID: "dockerfile-unpublished", Platform: "Dockerfile", Tests: &datadog.RuleTests{}},
		{ID: "dockerfile-untested", Platform: "Dockerfile", IsPublished: true},
	}}
	libraries := map[string]datadog.Library{
		"common":     {ID: "common", RegoCode: "package generic.common\n"},
		"dockerfile": {ID: "dockerfile", RegoCode: "package generic.dockerfile\n"},
	}
	for name, v := range map[string]any{"rules.json": ruleset, "libraries.json": libraries} {
		b, err := json.Marshal(v)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), b, 0o600))
	}
	client, err := datadog.NewLocalFileClient(filepath.Join(dir, "rules.json"), filepath.Join(dir, "libraries.json"))
	require.NoError(t, err)

	ctx := context.Background()
	suite, err := LoadAPI(ctx, client)
	require.NoError(t, err)
	require.Len(t, suite.Rules, 1)
	assert.Equal(t, "legacy-add", suite.Rules[0].LegacyID)

	res, err := suite.Run(ctx, suite.Rules[0], Options{})
	require.NoError(t, err)
	assert.True(t, res.Passed(), "%v", res.Mismatches)
}
