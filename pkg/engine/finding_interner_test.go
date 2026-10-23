/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

// Equal parts of findings are shared; parts that differ are not.
func TestFindingInterner_SharesOnlyEqualParts(t *testing.T) {
	in := newFindingInterner()

	a := strings.Repeat("x", 8)
	b := strings.Repeat("x", 8)
	require.Equal(t, unsafe.StringData(a), unsafe.StringData(in.string(a)))
	require.Equal(t, unsafe.StringData(a), unsafe.StringData(in.string(b)), "an equal string is the one seen first")
	require.Equal(t, "y", in.string("y"))

	lines := &[]model.CodeLine{{Position: 2, Line: "a"}, {Position: 3, Line: "b"}}
	same := &[]model.CodeLine{{Position: 2, Line: "a"}, {Position: 3, Line: "b"}}
	other := &[]model.CodeLine{{Position: 2, Line: "a"}, {Position: 3, Line: "c"}}
	require.Same(t, lines, in.codeLines("f.tf", 3, lines))
	require.Same(t, lines, in.codeLines("f.tf", 3, same))
	require.Same(t, other, in.codeLines("f.tf", 3, other), "different lines at the same place are kept")
	require.Same(t, same, in.codeLines("g.tf", 3, same), "lines of another file are kept")

	var none *findingInterner
	require.Equal(t, "z", none.string("z"))
	require.Same(t, lines, none.codeLines("f.tf", 3, lines))
}

// A shared attribution is the one building it for the finding gives.
func TestFindingInterner_AttributionMatchesBuildingIt(t *testing.T) {
	base := &model.ModuleAttribution{
		Source: "../modules/m",
		Arguments: []model.ModuleArgument{
			{LineStart: 3, LineEnd: 3, Control: model.ArgumentControlCaller, CallSite: model.SourceLocation{Filename: "root.tf", LineStart: 9}},
		},
		CallSite: model.SourceLocation{Filename: "root.tf", LineStart: 1},
	}
	attrs := map[string]*model.ModuleAttribution{moduleAttributionKey("aws_s3_bucket", 1, 1): base}
	finding := func(line int) *model.Vulnerability {
		return &model.Vulnerability{
			ResourceType: "aws_s3_bucket", Line: line,
			BlockLocation:         model.ResourceLocation{Start: model.ResourceLine{Line: 1, Col: 1}},
			VulnerabilityLocation: model.ResourceLocation{Start: model.ResourceLine{Line: line, Col: 3}, End: model.ResourceLine{Line: line, Col: 9}},
		}
	}
	in := newFindingInterner()
	for _, line := range []int{3, 4, 3, 4} {
		got := in.attribution(attrs, finding(line))
		require.Equal(t, moduleAttributionForResource(attrs, finding(line)), got, "line %d", line)
	}
	require.Same(t, in.attribution(attrs, finding(3)), in.attribution(attrs, finding(3)))
	require.NotSame(t, in.attribution(attrs, finding(3)), in.attribution(attrs, finding(4)))
	require.Nil(t, in.attribution(nil, finding(3)))
}
