/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package runner

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	jsonParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/json"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// stubQueriesSource is a minimal in-memory source.QueriesSource for driving
// engine.NewInspector with a single ad-hoc rule.
type stubQueriesSource struct {
	queries []model.QueryMetadata
}

func (s *stubQueriesSource) GetQueries(_ context.Context, _ *source.QueryInspectorParameters) ([]model.QueryMetadata, error) {
	return s.queries, nil
}

func (s *stubQueriesSource) GetQueryLibrary(_ context.Context, platform string) (source.RegoLibraries, error) {
	return source.RegoLibraries{
		LibraryCode:      "package generic." + platform + "\n",
		LibraryInputData: "{}",
	}, nil
}

// cloudwatchLogMetricFilterRule mirrors the common pattern of iterating
// doc.resource.<type> directly, which would pick up a reserved key as a fake resource.
const cloudwatchLogMetricFilterRule = `package datadog

DatadogPolicy contains result if {
	some resourceName, resource in input.document[0].resource.aws_cloudwatch_log_metric_filter

	result := {
		"documentId": input.document[0].id,
		"resourceType": "aws_cloudwatch_log_metric_filter",
		"resourceName": resourceName,
		"searchKey": sprintf("aws_cloudwatch_log_metric_filter[%s]", [resourceName]),
	}
}
`

// TestInspect_TFPlanMetaNotExposedAsFakeResource is a regression test:
// _dd_tfplan_meta must never surface as a fake resource to Rego rules.
func TestInspect_TFPlanMetaNotExposedAsFakeResource(t *testing.T) {
	ctx := context.Background()

	planJSON := []byte(`{
		"format_version": "1.2",
		"terraform_version": "1.5.0",
		"planned_values": {
			"root_module": {
				"resources": [
					{
						"address": "aws_cloudwatch_log_metric_filter.errors",
						"mode": "managed",
						"type": "aws_cloudwatch_log_metric_filter",
						"name": "errors",
						"values": {
							"name": "errors",
							"pattern": "ERROR"
						}
					}
				]
			}
		},
		"resource_changes": [
			{
				"address": "aws_cloudwatch_log_metric_filter.errors",
				"change": {
					"after_unknown": {"id": true}
				}
			}
		],
		"configuration": {
			"root_module": {
				"resources": [
					{
						"address": "aws_cloudwatch_log_metric_filter.errors",
						"expressions": {
							"pattern": {"constant_value": "ERROR"}
						}
					}
				]
			}
		}
	}`)

	p := &jsonParser.Parser{}
	_, docs, _, _, err := p.Parse(ctx, planJSON, "tfplan.json", false, 15)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	kind, ok := p.KindForContent(planJSON)
	require.True(t, ok)
	require.Equal(t, model.KindTerraformPlan, kind)

	prepared := PrepareScanDocument(ctx, docs[0], kind)
	require.Contains(t, prepared, "_dd_tfplan_meta",
		"sanity check: the document must actually carry _dd_tfplan_meta for this test to be meaningful")

	doc := model.FileMetadata{
		ID:                uuid.NewString(),
		ScanID:            "test",
		Document:          prepared,
		LineInfoDocument:  prepared,
		Kind:              model.KindTerraformPlan,
		FilePath:          "tfplan.json",
		OriginalData:      string(planJSON),
		LinesOriginalData: utils.SplitLines(string(planJSON)),
	}

	queries := []model.QueryMetadata{{
		Query:       "cloudwatch_log_metric_filter_rule",
		Content:     cloudwatchLogMetricFilterRule,
		InputData:   "{}",
		Platform:    "terraform",
		Metadata:    map[string]any{"id": "cloudwatch-log-metric-filter-rule"},
		Aggregation: 1,
	}}

	trk, err := tracker.NewTracker(3)
	require.NoError(t, err)

	ins, err := engine.NewInspector(
		ctx,
		&stubQueriesSource{queries: queries},
		engine.DefaultVulnerabilityBuilder,
		trk,
		&source.QueryInspectorParameters{},
		nil,
		".",
		false,
		false,
		1,
		featureflags.NewLocalEvaluator(),
		vfs.DiskFS{},
		false,
	)
	require.NoError(t, err)

	vulns, err := ins.Inspect(ctx, "test", model.FileMetadatas{&doc}, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries(), "no query should fail")

	require.Len(t, vulns, 1, "expected exactly one finding, for the real resource")
	require.Equal(t, "errors", vulns[0].ResourceName)

	for _, v := range vulns {
		require.NotEqual(t, "_dd_tfplan_meta", v.ResourceName,
			"_dd_tfplan_meta must never be reported as a resource")
	}
}
