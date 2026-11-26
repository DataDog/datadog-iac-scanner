/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package terragrunt

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/assert"
)

func TestRemapLines(t *testing.T) {
	table := model.LineTable{
		{FromLine: 1, ToLine: 1, Argument: "", Real: model.SourceLocation{LineStart: 10}},
		{FromLine: 2, ToLine: 2, Argument: "source", Real: model.SourceLocation{LineStart: 10}},
		{FromLine: 3, ToLine: 6, Argument: "list", Real: model.SourceLocation{LineStart: 20}},
		{FromLine: 7, ToLine: 7, Argument: "", Real: model.SourceLocation{LineStart: 10}},
	}
	block := model.Document{
		"list": []interface{}{},
		"_dd_lines": map[string]model.LineObject{
			"_dd__default": {Line: 1},
			"_dd_source":   {Line: 2},
			"_dd_list": {Line: 3, Arr: []map[string]*model.LineObject{
				{"_dd__default": {Line: 5}},
				{"_dd__default": {Arr: []map[string]*model.LineObject{{"_dd__default": {Line: 6}}}}},
			}},
			"_dd_out": {Line: 99},
		},
	}
	doc := model.Document{
		"module":    model.Document{"terragrunt": block},
		"_dd_lines": map[string]model.LineObject{"_dd_module": {Line: 1}},
	}

	RemapLines(doc, table, "")

	lines := block["_dd_lines"].(map[string]model.LineObject)
	assert.Equal(t, 10, lines["_dd__default"].Line)
	assert.Equal(t, 10, lines["_dd_source"].Line)
	assert.Equal(t, 20, lines["_dd_list"].Line)
	assert.Equal(t, 10, lines["_dd_out"].Line, "an unmapped line maps to the anchor")
	arr := lines["_dd_list"].Arr
	assert.Equal(t, 20, arr[0]["_dd__default"].Line)
	assert.Equal(t, 0, arr[1]["_dd__default"].Line)
	assert.Equal(t, 20, arr[1]["_dd__default"].Arr[0]["_dd__default"].Line)
	assert.Equal(t, 10, doc["_dd_lines"].(map[string]model.LineObject)["_dd_module"].Line)
}

func TestRemapLinesValueFromAnotherFile(t *testing.T) {
	table := model.LineTable{
		{FromLine: 1, ToLine: 1, Argument: "", Real: model.SourceLocation{Filename: "/r/root.hcl", LineStart: 5}},
		{FromLine: 2, ToLine: 2, Argument: "source", Real: model.SourceLocation{Filename: "/r/root.hcl", LineStart: 5}},
		{FromLine: 3, ToLine: 3, Argument: "own", Real: model.SourceLocation{Filename: "/r/u/terragrunt.hcl", LineStart: 7}},
		{FromLine: 4, ToLine: 4, Argument: "shared", Real: model.SourceLocation{Filename: "/r/root.hcl", LineStart: 9}},
		{FromLine: 5, ToLine: 5, Argument: "", Real: model.SourceLocation{Filename: "/r/root.hcl", LineStart: 5}},
	}
	block := model.Document{"_dd_lines": map[string]model.LineObject{
		"_dd_own": {Line: 3}, "_dd_shared": {Line: 4}, "_dd__default": {Line: 1},
	}}
	RemapLines(model.Document{"module": block}, table, "/r/u/terragrunt.hcl")
	lines := block["_dd_lines"].(map[string]model.LineObject)
	assert.Equal(t, 7, lines["_dd_own"].Line)
	assert.Equal(t, 7, lines["_dd_shared"].Line, "a value of another file maps into the unit file")
	assert.Equal(t, 7, lines["_dd__default"].Line)
}
