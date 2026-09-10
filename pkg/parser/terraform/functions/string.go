/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"strings"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

var StartsWithFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "str", Type: cty.String},
		{Name: "prefix", Type: cty.String},
	},
	Type: function.StaticReturnType(cty.Bool),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		return cty.BoolVal(strings.HasPrefix(args[0].AsString(), args[1].AsString())), nil
	},
})

var EndsWithFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "str", Type: cty.String},
		{Name: "suffix", Type: cty.String},
	},
	Type: function.StaticReturnType(cty.Bool),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		return cty.BoolVal(strings.HasSuffix(args[0].AsString(), args[1].AsString())), nil
	},
})

var StrContainsFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "str", Type: cty.String},
		{Name: "substr", Type: cty.String},
	},
	Type: function.StaticReturnType(cty.Bool),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		return cty.BoolVal(strings.Contains(args[0].AsString(), args[1].AsString())), nil
	},
})
