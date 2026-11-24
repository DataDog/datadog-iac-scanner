/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package runner

import (
	"bytes"
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/storage"
	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	jsonParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/json"
	"github.com/stretchr/testify/require"
)

const countedPlan = `{"format_version": "1.0", "planned_values": {"root_module": {"resources": [
	{"address": "aws_s3_bucket.main", "type": "aws_s3_bucket", "name": "main", "values": {"acl": "private"}}]}}}`

// TestSink_countsParsedTerraformPlans checks that a scan counts the files it
// parsed as Terraform plans, once each, and not a file that only looks like a
// plan, which keeps the plan kind as a plain JSON document.
func TestSink_countsParsedTerraformPlans(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  int
	}{
		{
			name: "two plans among other JSON files",
			files: map[string]string{
				"plans/a.tfplan.json":  countedPlan,
				"plans/b.tfplan.json":  countedPlan,
				"looks_like_plan.json": `{"format_version": "1.0", "planned_values": {}}`,
				"other.json":           `{"key": "value"}`,
			},
			want: 2,
		},
		{
			name: "nested plan markers under a top-level resource map",
			files: map[string]string{
				"looks_like_plan.json": `{"resource": {}, "plan": {"format_version": "1.0", "planned_values": {}}}`,
			},
			want: 0,
		},
		{
			name: "no plan",
			files: map[string]string{
				"looks_like_plan.json": `{"format_version": "1.0", "planned_values": {}}`,
				"other.json":           `{"key": "value"}`,
			},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			parsers, err := parser.NewBuilder(ctx).Add(&jsonParser.Parser{}).Build([]string{""}, []string{""})
			require.NoError(t, err)
			tr, err := tracker.NewTracker(3)
			require.NoError(t, err)
			s := &Service{
				Parser:      parsers[0],
				Storage:     storage.NewMemoryStorage(),
				Tracker:     tr,
				MaxFileSize: 5,
			}
			for name, content := range tt.files {
				require.NoError(t, sinkReader(s, ctx, name, "scanID",
					bytes.NewReader([]byte(content)), make([]byte, mbConst), false, 15))
			}
			// The same plan sunk again is still one plan.
			if tt.want > 0 {
				require.NoError(t, sinkReader(s, ctx, "plans/a.tfplan.json", "scanID",
					bytes.NewReader([]byte(countedPlan)), make([]byte, mbConst), false, 15))
			}

			require.Equal(t, tt.want, tr.ParsedTerraformPlans)
			lookAlikeSunk := false
			for _, file := range s.files {
				if file.FilePath == "looks_like_plan.json" {
					lookAlikeSunk = true
					require.Equal(t, model.KindTerraformPlan, file.Kind,
						"content that looks like a plan keeps the plan kind")
				}
			}
			require.True(t, lookAlikeSunk)
		})
	}
}
