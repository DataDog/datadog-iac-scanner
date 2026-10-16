/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package terraform

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestDocCursorCountsRepeatedBlocks(t *testing.T) {
	doc := model.Document{
		"resource": map[string]interface{}{
			"aws_sg": map[string]interface{}{
				"sg": map[string]interface{}{
					"ingress": []interface{}{
						map[string]interface{}{"cidr": "a"},
						map[string]interface{}{"cidr": "b"},
					},
					"egress": map[string]interface{}{"cidr": "c"},
				},
			},
		},
		"data": map[string]interface{}{
			"aws_ami": map[string]interface{}{
				"x": map[string]interface{}{"filter": []interface{}{map[string]interface{}{}}},
			},
		},
	}
	tests := []struct {
		name  string
		parts []string
		want  int
	}{
		{"bare type and name", []string{"aws_sg[sg]", "ingress[1]"}, 2},
		{"resource keyword", []string{"resource", "aws_sg[sg]", "ingress[0]"}, 2},
		{"single block indexed", []string{"aws_sg[sg]", "egress[0]"}, 1},
		{"data source", []string{"data", "aws_ami[x]", "filter[0]"}, 1},
		{"unknown resource", []string{"aws_sg[other]", "ingress[0]"}, unknownTotal},
		{"unindexed part", []string{"aws_sg[sg]", "ingress"}, unknownTotal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cursor := newDocCursor(doc, nil)
			got := unknownBlocks
			for _, part := range tt.parts {
				got = cursor.advance(part)
			}
			require.Equal(t, tt.want, got.total)
		})
	}
	require.Equal(t, unknownBlocks, newDocCursor(nil, nil).advance("aws_sg[sg]"))
}

func TestDocCursorReadsSourceLinesOfRepeatedBlocks(t *testing.T) {
	block := func(line int) map[string]interface{} {
		return map[string]interface{}{
			"_dd_lines": map[string]model.LineObject{"_dd__default": {Line: line}},
		}
	}
	generic := map[string]interface{}{
		"_dd_lines": map[string]interface{}{
			"_dd__default": map[string]interface{}{"_dd_line": float64(12)},
		},
	}
	tests := []struct {
		name     string
		ingress  interface{}
		want     repeatedBlocks
		wantNode bool
	}{
		{"line tables", []interface{}{block(3), block(3), block(9)}, repeatedBlocks{total: 3, lines: []int{2, 2, 8}}, true},
		{"decoded line tables", []interface{}{generic}, repeatedBlocks{total: 1, lines: []int{11}}, true},
		{"single block", block(5), repeatedBlocks{total: 1, lines: []int{4}}, true},
		{"one block without a line", []interface{}{block(3), map[string]interface{}{}}, repeatedBlocks{total: 2}, true},
		{"no line tables", []interface{}{map[string]interface{}{}}, repeatedBlocks{total: 1}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := model.Document{"resource": map[string]interface{}{
				"aws_sg": map[string]interface{}{"sg": map[string]interface{}{"ingress": tt.ingress}},
			}}
			cursor := newDocCursor(doc, nil)
			cursor.advance("aws_sg[sg]")
			require.Equal(t, tt.want, cursor.advance("ingress[0]"))
		})
	}
}

func TestWithSourceLines(t *testing.T) {
	lines := []int{1, 1, 5}
	tests := []struct {
		name     string
		scan     repeatedBlocks
		lineInfo repeatedBlocks
		want     repeatedBlocks
	}{
		{"lines of the line-info document join the scan count", repeatedBlocks{total: 3}, repeatedBlocks{total: 3, lines: lines}, repeatedBlocks{total: 3, lines: lines}},
		{"line-info document with another count is ignored", repeatedBlocks{total: 4}, repeatedBlocks{total: 3, lines: lines}, repeatedBlocks{total: 4}},
		{"line-info document without lines is ignored", repeatedBlocks{total: 3}, repeatedBlocks{total: 3}, repeatedBlocks{total: 3}},
		{"scan document saying nothing defers to the line-info document", unknownBlocks, repeatedBlocks{total: 3, lines: lines}, repeatedBlocks{total: 3, lines: lines}},
		{"scan document lines are kept when there is no line-info document", repeatedBlocks{total: 3, lines: lines}, unknownBlocks, repeatedBlocks{total: 3, lines: lines}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, withSourceLines(tt.scan, tt.lineInfo))
		})
	}
}
