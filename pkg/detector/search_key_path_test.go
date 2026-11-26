/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com/)  Copyright 2024 Datadog, Inc.
 */

package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSearchKeyPathPolicies(t *testing.T) {
	for _, tc := range []struct {
		name           string
		key            string
		cloudFormation []string
		structural     []string
		segments       []string
		expanded       []string
		legacy         []string
		legacyAnchored bool
		text           []string
	}{
		{
			name:           "wrapped key with a dot, brackets and equals",
			key:            "Resources.{{Bucket.Name[0]=blue}}.Properties",
			cloudFormation: []string{"Resources", "Bucket.Name[0]=blue", "Properties"},
			structural:     []string{"Resources", "{{Bucket", "Name", "0"},
			segments:       []string{"Resources", "{{0}}", "Properties"},
			expanded:       []string{"Resources", "Bucket.Name", "0", "=blue", "Properties"},
			legacy:         []string{"Resources", "Bucket.Name[0]=blue", "Properties"},
			text:           []string{"Resources", "{{0}}", "Properties"},
		},
		{
			name:           "dot in a quoted bracket key",
			key:            `Resources.labels["foo.bar"].Properties`,
			cloudFormation: []string{"Resources", "labels", `"foo.bar"`, "Properties"},
			structural:     []string{"Resources", "labels", `"foo.bar"`, "Properties"},
			segments:       []string{"Resources", `labels["foo.bar"]`, "Properties"},
			expanded:       []string{"Resources", "labels", "foo.bar", "Properties"},
			legacy:         []string{"Resources", "labels", "foo.bar", "Properties"},
			text:           []string{"Resources", `labels["foo`, `bar"]`, "Properties"},
		},
		{
			name:           "mid-path value anchor",
			key:            "Resources.name={{blue.green}}.Properties[0]",
			cloudFormation: []string{"Resources", "name"},
			structural:     []string{"Resources", "name"},
			segments:       []string{"Resources", "name={{0}}", "Properties[0]"},
			expanded:       []string{"Resources", "name=blue.green", "Properties", "0"},
			legacy:         []string{"Resources", "name", "Properties", "0"},
			legacyAnchored: true,
			text:           []string{"Resources", "name={{0}}", "Properties[0]"},
		},
		{
			name:           "wrapped key inside brackets",
			key:            "Resources[{{Bucket.Name[0]=blue}}].Properties[1]",
			cloudFormation: []string{"Resources", "Bucket.Name[0]=blue", "Properties", "1"},
			structural:     []string{"Resources"},
			segments:       []string{"Resources[{{0}}]", "Properties[1]"},
			expanded:       []string{"Resources", "Bucket.Name[0]=blue", "Properties", "1"},
			legacy:         []string{"Resources", "Bucket.Name[0]=blue", "Properties", "1"},
			text:           []string{"Resources[{{0}}]", "Properties[1]"},
		},
		{
			name:           "escaped quote and closing bracket inside a key",
			key:            `Resources.labels["west\"]eu.v1"].Properties[0]`,
			cloudFormation: []string{"Resources", "labels", `"west\"]eu.v1"`, "Properties", "0"},
			structural:     []string{"Resources", "labels", `"west\"]eu.v1"`, "Properties", "0"},
			segments:       []string{"Resources", `labels["west\"]eu.v1"]`, "Properties[0]"},
			expanded:       []string{"Resources", "labels", `west"]eu.v1`, "Properties", "0"},
			legacy:         []string{"Resources", "labels", `west"]eu.v1`, "Properties", "0"},
			text:           []string{"Resources", `labels["west\"]eu`, `v1"]`, "Properties[0]"},
		},
		{
			name:           "reference with a dotted value",
			key:            "Resources.$ref=#/schemas/v1.0.Foo",
			cloudFormation: []string{"Resources", "$ref"},
			structural:     []string{"Resources", "$ref"},
			segments:       []string{"Resources", "$ref=#/schemas/v1.0.Foo"},
			expanded:       []string{"Resources", "$ref=#/schemas/v1.0.Foo"},
			legacy:         []string{"Resources", "$ref=#/schemas/v1.0.Foo"},
			text:           []string{"Resources", "$ref=#/schemas/v1.0.Foo"},
		},
		{
			name:           "leading anchor and wrapped variant",
			key:            "name={{task-a}}.{{community.aws.ecs_ecr}}.policy.Statement[0].Principal",
			cloudFormation: []string{"name"},
			structural:     []string{"name"},
			segments:       []string{"name={{0}}", "{{1}}", "policy", "Statement[0]", "Principal"},
			expanded:       []string{"name=task-a", "community.aws.ecs_ecr", "policy", "Statement", "0", "Principal"},
			legacy:         []string{"name", "community.aws.ecs_ecr", "policy", "Statement", "0", "Principal"},
			legacyAnchored: true,
			text:           []string{"name={{0}}", "{{1}}", "policy", "Statement[0]", "Principal"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.cloudFormation, cloudFormationSearchPath(tc.key), "CloudFormation loop path")
			assert.Equal(t, tc.structural, expandSearchKeyPath(tc.key), "unprotected structural path")

			segments, extracted := splitSearchKeySegments(tc.key)
			assert.Equal(t, tc.segments, segments, "default anchored segments")
			assert.Equal(t, tc.expanded, expandKeyPath(segments, extracted), "default anchored expansion")

			legacy, anchored := LegacyPathComponents(tc.key)
			assert.Equal(t, tc.legacy, legacy, "legacy path components")
			assert.Equal(t, tc.legacyAnchored, anchored, "legacy anchor detection")

			textSegments, textExtracted := splitLegacySearchKey(tc.key, splitLiteralDots)
			assert.Equal(t, tc.text, textSegments, "default text fallback segments")
			assert.Equal(t, extracted, textExtracted, "default placeholder extraction")
		})
	}
}
