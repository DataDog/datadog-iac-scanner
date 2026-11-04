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

const consoleLoginPattern = `{ ($.eventName = ConsoleLogin) && ($.additionalEventData.MFAUsed != \"Yes\") }`

// parsedPatternRule reports every block whose pattern the rule sees as a
// parse tree.
const parsedPatternRule = `package datadog

import rego.v1

DatadogPolicy contains result if {
	some doc in input.document
	some type, blocks in doc.resource
	some name, block in blocks
	startswith(block.pattern, "{\"_dd_filter_expr\"")
	result := {
		"documentId": doc.id,
		"resourceType": type,
		"resourceName": name,
		"searchKey": sprintf("%s[%s].pattern", [type, name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "x",
		"keyActualValue": "y",
	}
}
`

func metricFilter(name, extra string) string {
	return `resource "aws_cloudwatch_log_metric_filter" "` + name + `" {
` + extra + `  name           = "f"
  pattern        = "` + consoleLoginPattern + `"
  log_group_name = "lg"
}
`
}

// A metric filter's pattern reaches rules parsed whether the block is
// written once, expanded by count, or instantiated from a module. A pattern
// attribute of any other resource type is left as written.
func TestInspect_MetricFilterPatternIsParsedOnEveryDocument(t *testing.T) {
	root := t.TempDir()
	sources := map[string]string{
		"main.tf": metricFilter("plain", "") + metricFilter("counted", "  count = 1\n") +
			"module \"child\" {\n  source = \"./child\"\n}\n" +
			"resource \"aws_other\" \"o\" {\n  pattern = \"" + consoleLoginPattern + "\"\n}\n",
		"child/main.tf": metricFilter("f", ""),
	}
	var files model.FileMetadatas
	for name, content := range sources {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		files = append(files, parseTerraform(t, path)...)
	}
	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "parsed_pattern", Content: parsedPatternRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "parsed-pattern", "platform": "Terraform"}, Aggregation: 1,
		}},
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	var got []string
	for i := range vulns {
		got = append(got, vulns[i].ResourceID)
	}
	require.ElementsMatch(t, []string{
		"aws_cloudwatch_log_metric_filter.plain",
		"aws_cloudwatch_log_metric_filter.counted[0]",
		"module.child.aws_cloudwatch_log_metric_filter.f",
	}, got)
}

// Documents share subtrees: parsing one document's patterns leaves the
// others as they are, and each is parsed once.
func TestParseTerraformFilterPatterns_CopiesSharedSubtrees(t *testing.T) {
	raw := strings.ReplaceAll(consoleLoginPattern, `\"`, `"`)
	shared := map[string]interface{}{
		metricFilterType: map[string]interface{}{"f": map[string]interface{}{"pattern": raw}},
	}
	plan := &model.FileMetadata{Kind: model.KindTerraformPlan, Document: model.Document{"resource": shared}}
	yaml := &model.FileMetadata{Kind: model.KindYAML, Document: model.Document{"resource": shared}}
	moduleDoc := model.Document{"resource": shared}

	parseTerraformValues(context.Background(), model.FileMetadatas{plan, yaml}, []model.Document{moduleDoc})

	pattern := func(doc model.Document) string {
		return doc["resource"].(map[string]interface{})[metricFilterType].(map[string]interface{})["f"].(map[string]interface{})["pattern"].(string)
	}
	parsed := ParseFilterPattern(raw)
	require.True(t, strings.HasPrefix(parsed, `{"_dd_filter_expr"`))
	require.Equal(t, parsed, pattern(plan.Document))
	require.Equal(t, parsed, pattern(moduleDoc))
	require.Equal(t, raw, pattern(yaml.Document), "only Terraform documents are parsed")
	require.Equal(t, raw, pattern(model.Document{"resource": shared}), "the shared subtree is not written to")
	require.Equal(t, "{ unbalanced", ParseFilterPattern("{ unbalanced"), "a pattern that does not parse is kept")
}
