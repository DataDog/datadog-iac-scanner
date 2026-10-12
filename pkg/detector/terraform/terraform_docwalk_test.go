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
			got := unknownTotal
			for _, part := range tt.parts {
				got = cursor.advance(part)
			}
			require.Equal(t, tt.want, got)
		})
	}
	require.Equal(t, unknownTotal, newDocCursor(nil, nil).advance("aws_sg[sg]"))
}
