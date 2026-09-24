/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com/)  Copyright 2024 Datadog, Inc.
 */

package detector

import (
	"strconv"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ansibleLineInfoDoc mirrors the line-info document for a playbook task
// holding an inline policy with a wildcard Principal statement.
func ansibleLineInfoDoc() map[string]interface{} {
	return map[string]interface{}{
		"_path": "/tmp/playbook.yaml",
		"playbooks": []interface{}{
			map[string]interface{}{
				"name": "task-a",
				"community.aws.ecs_ecr": map[string]interface{}{
					"name": "repo-a",
					"policy": map[string]interface{}{
						"Statement": []interface{}{
							map[string]interface{}{
								"Effect":    "Allow",
								"Principal": "*",
							},
						},
						"_dd_lines": map[string]interface{}{
							"_dd_Statement": &model.LineObject{
								Line: 6,
								Arr: []map[string]*model.LineObject{
									{
										"_dd_Principal": &model.LineObject{Line: 7},
										"_dd_Action":    &model.LineObject{Line: 10},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func TestResolveAnchoredPath(t *testing.T) {
	doc := ansibleLineInfoDoc()

	segments, extracted := splitSearchKeySegments("name={{task-a}}.{{community.aws.ecs_ecr}}.policy.Statement[0].Principal")
	require.Len(t, extracted, 2)

	comps, ok := resolveAnchoredPath(segments, extracted, doc)
	require.True(t, ok)
	assert.Equal(t, []string{"playbooks", "0", "community.aws.ecs_ecr", "policy", "Statement", "0", "Principal"}, comps)

	// Dotted numeric indices resolve identically.
	segments, extracted = splitSearchKeySegments("name={{task-a}}.{{community.aws.ecs_ecr}}.policy.Statement.0.Principal")
	comps, ok = resolveAnchoredPath(segments, extracted, doc)
	require.True(t, ok)
	assert.Equal(t, []string{"playbooks", "0", "community.aws.ecs_ecr", "policy", "Statement", "0", "Principal"}, comps)
}

func TestResolveAnchoredPathRejections(t *testing.T) {
	doc := ansibleLineInfoDoc()

	for _, key := range []string{
		// Shallow keys keep the text-matching behavior.
		"name={{task-a}}.{{community.aws.ecs_ecr}}.policy",
		"name={{task-a}}.{{community.aws.ecs_ecr}}",
		// No value anchor in the root.
		"policy.Statement[0].Principal",
		// Deep but no numeric index.
		"name={{task-a}}.{{community.aws.ecs_ecr}}.policy.Version",
		// Unknown anchor value.
		"name={{task-b}}.{{community.aws.ecs_ecr}}.policy.Statement[0].Principal",
	} {
		segments, extracted := splitSearchKeySegments(key)
		_, ok := resolveAnchoredPath(segments, extracted, doc)
		assert.False(t, ok, "expected rejection for %q", key)
	}
}

func TestResolveAnchoredPathNestedArray(t *testing.T) {
	// Task hidden under a block: the anchor search must descend into nested
	// arrays to find it.
	doc := map[string]interface{}{
		"playbooks": []interface{}{
			map[string]interface{}{
				"name": "outer",
				"block": []interface{}{
					map[string]interface{}{
						"name": "task-a",
						"community.aws.ecs_ecr": map[string]interface{}{
							"policy": map[string]interface{}{
								"Statement": []interface{}{map[string]interface{}{"Principal": "*"}},
							},
						},
					},
				},
			},
		},
	}
	segments, extracted := splitSearchKeySegments("name={{task-a}}.{{community.aws.ecs_ecr}}.policy.Statement[0].Principal")
	comps, ok := resolveAnchoredPath(segments, extracted, doc)
	require.True(t, ok)
	assert.Equal(t, []string{"playbooks", "0", "block", "0", "community.aws.ecs_ecr", "policy", "Statement", "0", "Principal"}, comps)
}

func TestDetectAnchoredLine(t *testing.T) {
	lines := []string{
		"- name: task-a",
		"  community.aws.ecs_ecr:",
		"    name: repo-a",
		"    policy:",
		"      Statement:",
		"        - Effect: Allow",
		"          Principal: '*'",
	}
	file := &model.FileMetadata{
		LineInfoDocument:  ansibleLineInfoDoc(),
		LinesOriginalData: &lines,
	}

	res := detectAnchoredLine("name={{task-a}}.{{community.aws.ecs_ecr}}.policy.Statement[0].Principal", file, file.FilePath, 1, lines)
	require.NotNil(t, res)
	assert.Equal(t, 7, res.Line)

	// A shallow anchored key is not handled here (text matcher keeps it).
	assert.Nil(t, detectAnchoredLine("name={{task-a}}.{{community.aws.ecs_ecr}}.policy", file, file.FilePath, 1, lines))

	// A key anchored on an unknown task falls through.
	assert.Nil(t, detectAnchoredLine("name={{task-z}}.{{community.aws.ecs_ecr}}.policy.Statement[0].Principal", file, file.FilePath, 1, lines))
}

func TestSplitSearchKeySegmentsMatchesLegacySanitization(t *testing.T) {
	// For keys without bracketed dot groups the helper must match the inline
	// normalization DetectLine performs.
	searchKey := "name={{task-a}}.{{community.aws.ecs_ecr}}.policy.Statement[0].Principal"

	split, extracted := splitSearchKeySegments(searchKey)

	var legacyExtracted [][]string
	legacyExtracted = GetBracketValues(searchKey, legacyExtracted, "")
	sanitized := searchKey
	for idx, str := range legacyExtracted {
		sanitized = strings.ReplaceAll(sanitized, str[0], `{{`+strconv.Itoa(idx)+`}}`)
	}
	legacySplit := strings.Split(sanitized, ".")

	assert.Equal(t, legacySplit, split)
	assert.Equal(t, legacyExtracted, extracted)
}

func TestSplitSearchKeySegmentsPreservesBracketedDots(t *testing.T) {
	// Dots inside a bracket group must survive the split; expansion unquotes
	// the key so it addresses the map key foo.bar (see TestExpandBracketSegmentUnquotesKeys).
	split, _ := splitSearchKeySegments(`name={{task-a}}.{{community.aws.ecs_ecr}}.rules[0].labels["foo.bar"]`)
	assert.Equal(t, []string{
		"name={{0}}",
		"{{1}}",
		"rules[0]",
		`labels["foo.bar"]`,
	}, split)
}

func TestResolveAnchoredPathWithoutVariant(t *testing.T) {
	// A key anchored on an element that holds the target attribute directly,
	// with no {{variant}} segment in between.
	doc := map[string]interface{}{
		"roles": []interface{}{
			map[string]interface{}{
				"name": "role-a",
				"policy": map[string]interface{}{
					"Statement": []interface{}{map[string]interface{}{"Principal": "*"}},
					"_dd_lines": map[string]interface{}{
						"_dd_Statement": &model.LineObject{
							Line: 2,
							Arr: []map[string]*model.LineObject{
								{"_dd_Principal": &model.LineObject{Line: 4}},
							},
						},
					},
				},
			},
		},
	}
	segments, extracted := splitSearchKeySegments("name={{role-a}}.policy.Statement[0].Principal")
	require.Len(t, extracted, 1)

	comps, ok := resolveAnchoredPath(segments, extracted, doc)
	require.True(t, ok)
	assert.Equal(t, []string{"roles", "0", "policy", "Statement", "0", "Principal"}, comps)
}

func TestExpandBracketSegmentUnquotesKeys(t *testing.T) {
	assert.Equal(t, []string{"labels", "foo.bar"}, expandBracketSegment(`labels["foo.bar"]`))
	assert.Equal(t, []string{"Statement", "0"}, expandBracketSegment("Statement[0]"))
}
