/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"time"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

var TimeCmpFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "timestamp_a", Type: cty.String},
		{Name: "timestamp_b", Type: cty.String},
	},
	Type: function.StaticReturnType(cty.Number),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		a, err := time.Parse(time.RFC3339, args[0].AsString())
		if err != nil {
			return cty.NilVal, function.NewArgErrorf(0, "not a valid RFC3339 timestamp: %s", args[0].AsString())
		}
		b, err := time.Parse(time.RFC3339, args[1].AsString())
		if err != nil {
			return cty.NilVal, function.NewArgErrorf(1, "not a valid RFC3339 timestamp: %s", args[1].AsString())
		}
		switch {
		case a.Equal(b):
			return cty.NumberIntVal(0), nil
		case a.Before(b):
			return cty.NumberIntVal(-1), nil
		default:
			return cty.NumberIntVal(1), nil
		}
	},
})
