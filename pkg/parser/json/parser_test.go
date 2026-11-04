/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package json

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/analyzer"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

var have = `{"martin":{"name":"Martin D'vloper"}}`

// TestParser_GetKind tests the functions [GetKind()] and all the methods called by them
func TestParser_GetKind(t *testing.T) {
	p := &Parser{}
	require.Equal(t, model.KindJSON, p.GetKind())
}

// TestParser_SupportedExtensions tests the functions [SupportedExtensions()] and all the methods called by them
func TestParser_SupportedExtensions(t *testing.T) {
	p := &Parser{}
	require.Equal(t, []string{".json"}, p.SupportedExtensions())
}

// TestParser_SupportedExtensions tests the functions [SupportedTypes()] and all the methods called by them
func TestParser_SupportedTypes(t *testing.T) {
	p := &Parser{}
	require.Equal(t, map[string]bool{
		"ansible":              true,
		"cloudformation":       true,
		"openapi":              true,
		"azureresourcemanager": true,
		"terraform":            true,
		"kubernetes":           true,
	}, p.SupportedTypes())
}

// TestParser_Parse tests the functions [Parse()] and all the methods called by them
func TestParser_Parse(t *testing.T) {
	ctx := context.Background()
	p := &Parser{}

	_, doc, _, _, err := p.Parse(ctx, []byte(have), "test.json", true, 15)
	require.NoError(t, err)
	require.Len(t, doc, 1)
	require.Contains(t, doc[0], "martin")
}

// Test_Resolve tests the functions [Resolve()] and all the methods called by them
func Test_Resolve(t *testing.T) {
	ctx := context.Background()
	parser := &Parser{}

	resolved, _, err := parser.Resolve(ctx, []byte(have), "test.json", true, 15)
	require.NoError(t, err)
	require.Equal(t, have, string(resolved))
}

// Test_GetCommentToken must get the token that represents a comment
func Test_GetCommentToken(t *testing.T) {
	parser := &Parser{}
	require.Equal(t, "", parser.GetCommentToken())
}

// minifiedTFPlan is a valid (minified) Terraform plan JSON
// parseTFPlan needs format_version/terraform_version and a planned_values tree.
const minifiedTFPlan = `{"format_version":"0.2","terraform_version":"1.0.5","planned_values":{"root_module":{"resources":[{"address":"fakewebservices_database.prod_db","mode":"managed","type":"fakewebservices_database","name":"prod_db","provider_name":"registry.terraform.io/hashicorp/fakewebservices","schema_version":0,"values":{"name":"Production DB","size":256},"sensitive_values":{}}]}},"resource_changes":[],"configuration":{}}`

func TestJSON_StringifyContent(t *testing.T) {
	// The indenting decision is now driven per-file by the content itself
	var indentedPlan bytes.Buffer
	require.NoError(t, json.Indent(&indentedPlan, []byte(minifiedTFPlan), "", "  "))

	tests := []struct {
		name    string
		content []byte
		want    string
		wantErr bool
	}{
		{
			name:    "non-plan JSON is returned unchanged (not indented)",
			content: []byte("{\n\t\t\t\t\t\"key\" : \"value\"\n\t\t\t\t}\n"),
			want:    "{\n\t\t\t\t\t\"key\" : \"value\"\n\t\t\t\t}\n",
			wantErr: false,
		},
		{
			name:    "minified non-plan JSON stays minified",
			content: []byte(`{"key":"value"}`),
			want:    `{"key":"value"}`,
			wantErr: false,
		},
		{
			name:    "terraform plan JSON is indented",
			content: []byte(minifiedTFPlan),
			want:    indentedPlan.String(),
			wantErr: false,
		},
	}

	for i := range tests {
		tt := &tests[i]
		t.Run(tt.name, func(t *testing.T) {
			var p Parser
			got, err := p.StringifyContent(tt.content)
			require.Equal(t, tt.wantErr, (err != nil))
			require.Equal(t, tt.want, got)
		})
	}
}

func TestParsePlanLinesFollowStringifiedContent(t *testing.T) {
	p := &Parser{}
	_, docs, _, _, err := p.Parse(context.Background(), []byte(minifiedTFPlan), "plan.json", false, 15)
	require.NoError(t, err)
	shown, err := p.StringifyContent([]byte(minifiedTFPlan))
	require.NoError(t, err)
	lines := strings.Split(shown, "\n")

	lineAt := func(path ...string) int {
		var node interface{} = map[string]interface{}(docs[0])
		for _, key := range path {
			node = node.(map[string]interface{})[key]
		}
		return int(node.(float64))
	}
	header := lineAt("resource", "fakewebservices_database", "_dd_lines", "_dd_prod_db", "_dd_line")
	require.Contains(t, lines[header-1], `"values": {`)
	size := lineAt("resource", "fakewebservices_database", "prod_db", "_dd_lines", "_dd_size", "_dd_line")
	require.Contains(t, lines[size-1], `"size": 256`)
}

// TestJSON_StringifyContent_NoCrossFileState guards the parallel-parsing
func TestJSON_StringifyContent_NoCrossFileState(t *testing.T) {
	ctx := context.Background()
	p := &Parser{}
	const nonPlan = `{"apiVersion":"v1","kind":"Pod"}`

	_, _, _, _, err := p.Parse(ctx, []byte(minifiedTFPlan), "plan.json", false, 15)
	require.NoError(t, err)

	got, err := p.StringifyContent([]byte(nonPlan))
	require.NoError(t, err)
	require.Equal(t, nonPlan, got,
		"non-plan content was reformatted after a plan was parsed — parser carries shared cross-file state")
}

// TestJSON_StringifyContent_ConcurrentNonPlan is the parallel flavor: a non-plan
// file stringified concurrently with plans being parsed on the same *Parser must
// always be raw. Run with -race!
func TestJSON_StringifyContent_ConcurrentNonPlan(t *testing.T) {
	ctx := context.Background()
	p := &Parser{}
	const nonPlan = `{"apiVersion":"v1","kind":"Pod"}`
	const n = 500

	results := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); _, _, _, _, _ = p.Parse(ctx, []byte(minifiedTFPlan), "plan.json", false, 15) }()
		go func(idx int) {
			defer wg.Done()
			got, _ := p.StringifyContent([]byte(nonPlan))
			results[idx] = got // each goroutine writes its own index: no shared-slice race
		}(i)
	}
	wg.Wait()

	for i, got := range results {
		require.Equalf(t, nonPlan, got, "iter %d: non-plan content was reformatted (shared parser state leaked)", i)
	}
}

// The parser reads as a plan exactly what the analyzer classifies as one.
func TestParserPlanDetectionMatchesAnalyzer(t *testing.T) {
	for name, content := range map[string]string{
		"plan":                       `{"format_version":"1.2","terraform_version":"1.9.0","planned_values":{},"configuration":{}}`,
		"plan without configuration": `{"format_version":"1.2","terraform_version":"1.9.0","planned_values":{}}`,
		"no terraform_version":       `{"format_version":"1.2","planned_values":{},"configuration":{}}`,
		"keys as values":             `{"note":"format_version terraform_version planned_values"}`,
		"spaced keys":                "{\"format_version\" : \"1.2\", \"terraform_version\"\n: \"1.9.0\", \"planned_values\" :{}}",
		"state":                      `{"format_version":"1.0","terraform_version":"1.9.0","values":{}}`,
		"cloudformation":             `{"AWSTemplateFormatVersion":"2010-09-09","Resources":{}}`,
	} {
		kind, isPlan := (&Parser{}).KindForContent([]byte(content))
		require.Equal(t, analyzer.IsTerraformPlan([]byte(content)), isPlan, name)
		if isPlan {
			require.Equal(t, model.KindTerraformPlan, kind, name)
		}
	}
	_, isPlan := (&Parser{}).KindForContent([]byte(`{"format_version":"1.2","planned_values":{}}`))
	require.False(t, isPlan, "a plan has a terraform_version")
}
