package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/rulefixture"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
)

func TestShouldRunRule(t *testing.T) {
	rule := &datadog.Rule{
		ID:          "platform-provider-slug",
		Platform:    "Terraform",
		IsPublished: true,
		LegacyId:    func() *string { s := "old-legacy-id"; return &s }(),
		LegacyIds:   []string{"renamed-away-id", "merged-rule-id"},
		Tests:       &datadog.RuleTests{},
	}

	for _, tc := range []struct {
		name       string
		platform   []string
		ruleFilter []string
		wantRun    bool
	}{
		{name: "no_filter_runs", ruleFilter: nil, wantRun: true},
		{name: "canonical_id", ruleFilter: []string{"platform-provider-slug"}, wantRun: true},
		{name: "legacy_id", ruleFilter: []string{"old-legacy-id"}, wantRun: true},
		{name: "legacy_ids_entry", ruleFilter: []string{"merged-rule-id"}, wantRun: true},
		{name: "unknown_id_skipped", ruleFilter: []string{"unrelated-id"}, wantRun: false},
		{name: "platform_mismatch_skipped", platform: []string{"Dockerfile"}, ruleFilter: []string{"platform-provider-slug"}, wantRun: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			platformFilter := tc.platform
			if platformFilter == nil {
				platformFilter = []string{"Terraform"}
			}
			require.Equal(t, tc.wantRun, shouldRunRule(rule, platformFilter, tc.ruleFilter))
		})
	}

	// A rule without tests is never selected, whatever the filter matches.
	untested := *rule
	untested.Tests = nil
	require.False(t, shouldRunRule(&untested, []string{"Terraform"}, []string{"platform-provider-slug"}))
}

func TestRuleFixtureCases(t *testing.T) {
	files := []datadog.TestFile{
		{FileName: "first.tf", Content: []byte(`resource "aws_s3_bucket" "same" {acl="public"}`)},
		{FileName: "second.tf", Content: []byte(`resource "aws_s3_bucket" "same" {acl="public"}`)},
		{FileName: "root.tf", Content: []byte("module \"bucket\" {\n source=\"./child\"\n acl=file(\"${path.module}/acl.txt\")\n}")},
		{FileName: "child/main.tf", Content: []byte("variable \"acl\" {default=\"private\"}\nresource \"aws_s3_bucket\" \"same\" {acl=var.acl}")},
		{FileName: "acl.txt", Content: []byte("public")},
		{FileName: "unowned.tf", Content: []byte(`invalid {`)},
	}
	expected := func(file string) datadog.TestFinding {
		return datadog.TestFinding{ShortDescription: "Fixture domains", Severity: "HIGH", Line: 1, FileName: file}
	}
	callSite := expected("root.tf")
	callSite.Line = 3
	definition := datadog.RuleTestCases{Version: 1, Cases: []datadog.RuleTestCase{
		{Name: "documents together", Input: datadog.RuleTestDocuments, Targets: []string{"first.tf", "second.tf"}, Assets: []string{"first.tf", "second.tf"}, Expected: []datadog.TestFinding{expected("first.tf"), expected("second.tf")}},
		{Name: "configuration and child metadata", Input: datadog.RuleTestConfiguration, Root: ".", Targets: []string{"root.tf", "child/main.tf"}, Assets: []string{"root.tf", "child/main.tf", "acl.txt"}, Expected: []datadog.TestFinding{callSite}},
	}}
	contents, err := json.Marshal(definition)
	require.NoError(t, err)
	suite, err := rulefixture.Load(&datadog.RuleTests{Files: append(files, datadog.TestFile{FileName: datadog.RuleTestCasesFile, Content: contents})})
	require.NoError(t, err)
	require.Equal(t, 2, suite.Len())
	input, err := suite.Prepare(0, t.TempDir())
	require.NoError(t, err)
	_, err = input.Filesystem.ReadFile(filepath.Join(input.Root, "unowned.tf"))
	require.Error(t, err)
	// The suite owns its source bytes independently of the transport payload.
	files[0].Content[0] = '!'
	frozen, err := input.Filesystem.ReadFile(input.Targets[0])
	require.NoError(t, err)
	require.True(t, bytes.HasPrefix(frozen, []byte("resource")))
	rule := &datadog.Rule{ID: "fixture-domains", Name: "fixture-domains", Platform: "Terraform", ShortDescription: "Fixture domains", Severity: "HIGH", Category: "Insecure Configurations", RegoQuery: []byte(`package datadog
import rego.v1
DatadogPolicy contains result if {
 some i
 input.document[i].resource.aws_s3_bucket.same.acl=="public"
 result:={"documentId":input.document[i].id,"resourceType":"aws_s3_bucket","resourceName":"same","searchKey":"aws_s3_bucket[same].acl"}
}`)}
	mismatches, err := runRuleTestCases(t.Context(), suite, rule, fixtureCaseLibraries{})
	require.NoError(t, err)
	require.Empty(t, mismatches)
	// Aggregate predicates observe the full explicit document set in one input.
	rule.RegoQuery = bytes.Replace(rule.RegoQuery, []byte("some i"), []byte("count(input.document)==2\n some i"), 1)
	docs := definition
	docs.Cases = docs.Cases[:1]
	data, err := json.Marshal(docs)
	require.NoError(t, err)
	files[0].Content[0] = 'r'
	suite, err = rulefixture.Load(&datadog.RuleTests{Files: append(files, datadog.TestFile{FileName: datadog.RuleTestCasesFile, Content: data})})
	require.NoError(t, err)
	mismatches, err = runRuleTestCases(t.Context(), suite, rule, fixtureCaseLibraries{})
	require.NoError(t, err)
	require.Empty(t, mismatches)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = runRuleTestCases(ctx, suite, rule, fixtureCaseLibraries{})
	require.ErrorIs(t, err, context.Canceled)
}

// A negative policy expectation cannot turn a parsing failure into a pass.
func TestRuleFixtureParsing(t *testing.T) {
	for _, domain := range []datadog.RuleTestInput{datadog.RuleTestDocuments, datadog.RuleTestConfiguration} {
		t.Run(string(domain), func(t *testing.T) {
			test := datadog.RuleTestCase{Name: "negative", Input: domain, Targets: []string{"bad.tf"}, Assets: []string{"bad.tf"}}
			if domain == datadog.RuleTestConfiguration {
				test.Root = "."
			}
			data, err := json.Marshal(datadog.RuleTestCases{Version: 1, Cases: []datadog.RuleTestCase{test}})
			require.NoError(t, err)
			suite, err := rulefixture.Load(&datadog.RuleTests{Files: []datadog.TestFile{
				{FileName: "bad.tf", Content: []byte(`resource "aws_s3_bucket" "broken" {`)},
				{FileName: datadog.RuleTestCasesFile, Content: data},
			}})
			require.NoError(t, err)
			_, err = runRuleTestCases(t.Context(), suite, &datadog.Rule{ID: "negative", Platform: "Terraform"}, fixtureCaseLibraries{})
			require.ErrorContains(t, err, "Unclosed configuration block")
		})
	}
}

func TestRuleFixtureCaseContract(t *testing.T) {
	valid := `{"version":1,"cases":[{"name":"documents","input":"documents","targets":["a.tf"],"assets":["a.tf"],"expected":[]}]}`
	for _, test := range []struct {
		name, manifest string
		valid          bool
	}{
		{"documents", valid, true},
		{"dot-prefixed filename", strings.ReplaceAll(valid, `"a.tf"`, `"..fixture.tf"`), true},
		{"configuration", strings.Replace(valid, `"input":"documents"`, `"input":"configuration","root":"."`, 1), true},
		{"version", strings.Replace(valid, `"version":1`, `"version":2`, 1), false},
		{"unknown field", strings.Replace(valid, `"version":1`, `"version":1,"skip":true`, 1), false},
		{"trailing value", valid + `{}`, false},
		{"empty cases", `{"version":1,"cases":[]}`, false},
		{"unknown domain", strings.Replace(valid, `"input":"documents"`, `"input":"automatic"`, 1), false},
		{"configuration needs root", strings.Replace(valid, `"input":"documents"`, `"input":"configuration"`, 1), false},
		{"documents have no root", strings.Replace(valid, `"input":"documents"`, `"input":"documents","root":"."`, 1), false},
		{"no targets", strings.Replace(valid, `"targets":["a.tf"]`, `"targets":[]`, 1), false},
		{"target ownership", strings.Replace(valid, `"assets":["a.tf"]`, `"assets":[]`, 1), false},
		{"missing asset", strings.ReplaceAll(valid, `"a.tf"`, `"missing.tf"`), false},
		{"duplicate target", strings.Replace(valid, `"targets":["a.tf"]`, `"targets":["a.tf","a.tf"]`, 1), false},
		{"duplicate asset", strings.Replace(valid, `"assets":["a.tf"]`, `"assets":["a.tf","a.tf"]`, 1), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			assetName := "a.tf"
			if test.name == "dot-prefixed filename" {
				assetName = "..fixture.tf"
			}
			suite, err := rulefixture.Load(&datadog.RuleTests{Files: []datadog.TestFile{{FileName: assetName, Content: []byte("value")}, {FileName: datadog.RuleTestCasesFile, Content: []byte(test.manifest)}}})
			if !test.valid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, suite)
		})
	}
	for _, name := range []string{"../a.tf", "/a.tf", "a/../a.tf", "a//b.tf", "C:/a.tf", `a\b.tf`, "."} {
		t.Run("path/"+name, func(t *testing.T) {
			definition := datadog.RuleTestCases{Version: 1, Cases: []datadog.RuleTestCase{{Name: "path", Input: datadog.RuleTestDocuments, Targets: []string{name}, Assets: []string{name}}}}
			data, err := json.Marshal(definition)
			require.NoError(t, err)
			_, err = rulefixture.Load(&datadog.RuleTests{Files: []datadog.TestFile{{FileName: name}, {FileName: datadog.RuleTestCasesFile, Content: data}}})
			require.Error(t, err)
		})
	}
	suite, err := rulefixture.Load(&datadog.RuleTests{Files: []datadog.TestFile{{FileName: "legacy.tf"}}})
	require.NoError(t, err)
	require.Nil(t, suite)
}

type fixtureCaseLibraries struct{}

func (fixtureCaseLibraries) GetQueries(context.Context, *source.QueryInspectorParameters) ([]model.QueryMetadata, error) {
	return nil, nil
}
func (fixtureCaseLibraries) GetQueryLibrary(_ context.Context, platform string) (source.RegoLibraries, error) {
	return source.RegoLibraries{LibraryCode: "package " + strings.ToLower(platform) + "\n", LibraryInputData: "{}"}, nil
}

func TestRuleFixturePathIdentity(t *testing.T) {
	expected := datadog.TestFinding{ShortDescription: "Paths", Severity: "HIGH", Line: 1, FileName: "a/main.tf"}
	definition := datadog.RuleTestCases{Version: 1, Cases: []datadog.RuleTestCase{{
		Name: "same basenames", Input: datadog.RuleTestDocuments,
		Targets: []string{"a/main.tf", "b/main.tf", "..fixture.tf"}, Assets: []string{"a/main.tf", "b/main.tf", "..fixture.tf"}, Expected: []datadog.TestFinding{expected},
	}}}
	data, err := json.Marshal(definition)
	require.NoError(t, err)
	rule := &datadog.Rule{ID: "paths", Name: "paths", Platform: "Terraform", ShortDescription: "Paths", Severity: "HIGH", RegoQuery: []byte(`package datadog
import rego.v1
DatadogPolicy contains result if {
 some i
 input.document[i].resource.aws_s3_bucket.same.acl=="public"
 result:={"documentId":input.document[i].id,"resourceType":"aws_s3_bucket","resourceName":"same","searchKey":"aws_s3_bucket[same].acl"}
}`)}
	fixtures := []datadog.TestFile{
		{FileName: "a/main.tf", Content: []byte(`resource "aws_s3_bucket" "same" {acl="public"}`)},
		{FileName: "b/main.tf", Content: []byte(`resource "aws_s3_bucket" "same" {acl="private"}`)},
		{FileName: "..fixture.tf", Content: []byte(`resource "aws_s3_bucket" "same" {acl="private"}`)},
		{FileName: datadog.RuleTestCasesFile, Content: data},
	}
	suite, err := rulefixture.Load(&datadog.RuleTests{Files: fixtures})
	require.NoError(t, err)
	mismatches, err := runRuleTestCases(t.Context(), suite, rule, fixtureCaseLibraries{})
	require.NoError(t, err)
	require.Empty(t, mismatches)
	fixtures[0].Content, fixtures[1].Content = fixtures[1].Content, fixtures[0].Content
	suite, err = rulefixture.Load(&datadog.RuleTests{Files: fixtures})
	require.NoError(t, err)
	mismatches, err = runRuleTestCases(t.Context(), suite, rule, fixtureCaseLibraries{})
	require.NoError(t, err)
	require.Len(t, mismatches, 2)
	require.Contains(t, strings.Join(mismatches, "\n"), "a/main.tf")
	require.Contains(t, strings.Join(mismatches, "\n"), "b/main.tf")
	input, err := suite.Prepare(0, t.TempDir())
	require.NoError(t, err)
	_, err = rulefixture.FindingPath(input.Root, input.Targets, filepath.Join(input.Root, "unowned.tf"))
	require.Error(t, err)
	_, err = rulefixture.FindingPath(input.Root, input.Targets, filepath.Join(input.Root, "..", "main.tf"))
	require.Error(t, err)
}

func TestRuleFixtureReferenceAssets(t *testing.T) {
	for _, format := range []string{"json", "yaml"} {
		t.Run(format, func(t *testing.T) {
			main := `{"openapi":"3.0.0","info":{"title":"fixture","version":"1"},"paths":{},"value":{"$ref":"./payload.json"}}`
			asset := `{"marker":"owned"}`
			if format == "yaml" {
				main = "openapi: 3.0.0\ninfo:\n  title: fixture\n  version: '1'\npaths: {}\nvalue:\n  $ref: ./payload.yaml\n"
				asset = "marker: owned\n"
			}
			target, payload := "main."+format, "payload."+format
			definition := datadog.RuleTestCases{Version: 1, Cases: []datadog.RuleTestCase{{Name: "references", Input: datadog.RuleTestDocuments, Targets: []string{target}, Assets: []string{target, payload}}}}
			data, err := json.Marshal(definition)
			require.NoError(t, err)
			suite, err := rulefixture.Load(&datadog.RuleTests{Files: []datadog.TestFile{{FileName: target, Content: []byte(main)}, {FileName: payload, Content: []byte(asset)}, {FileName: datadog.RuleTestCasesFile, Content: data}}})
			require.NoError(t, err)
			input, err := suite.Prepare(0, t.TempDir())
			require.NoError(t, err)
			// A conflicting physical neighbor cannot replace the owned reference bytes.
			require.NoError(t, os.WriteFile(filepath.Join(input.Root, payload), []byte(strings.ReplaceAll(asset, "owned", "unowned")), 0600))
			parsers, err := newFixtureParsers(t.Context(), input.Filesystem)
			require.NoError(t, err)
			binding := ruleFixtureInput{root: input.Root, files: input.Targets, fsys: input.Filesystem, domain: input.Domain, format: explicitRuleFixture}
			files, err := binding.parseFile(t.Context(), input.Targets[0], "OpenAPI", parsers)
			require.NoError(t, err)
			require.NotEmpty(t, files)
			for _, file := range files {
				require.Equal(t, "owned", file.Document["value"].(map[string]interface{})["marker"])
			}

			rule := &datadog.Rule{ID: "reference", Name: "reference", Platform: "OpenAPI", ShortDescription: "Reference", Severity: "HIGH", RegoQuery: []byte(`package datadog
import rego.v1
DatadogPolicy contains result if {
 some i
 input.document[i].value.marker=="owned"
 result:={"documentId":input.document[i].id,"searchKey":"value.marker"}
}`)}
			query := source.ConvertRule(rule)
			findings, shape, err := runFiles(t.Context(), rule.ID, &query, &binding, fixtureCaseLibraries{})
			require.NoError(t, err)
			require.Empty(t, shape)
			require.Len(t, findings, 1)
		})
	}
}
