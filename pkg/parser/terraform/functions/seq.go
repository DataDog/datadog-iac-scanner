/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"errors"
	"sort"

	"github.com/zclconf/go-cty/cty"
	ctyconvert "github.com/zclconf/go-cty/cty/convert"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
	"github.com/zclconf/go-cty/cty/gocty"
)

var AllTrueFunc = function.New(&function.Spec{
	Params: []function.Parameter{{
		Name: "list",
		Type: cty.List(cty.Bool),
	}},
	Type: function.StaticReturnType(cty.Bool),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		hasUnknown := false
		for it := args[0].ElementIterator(); it.Next(); {
			_, v := it.Element()
			if !v.IsKnown() {
				hasUnknown = true
				continue
			}
			if v.IsNull() || v.False() {
				return cty.False, nil
			}
		}
		if hasUnknown {
			return cty.UnknownVal(cty.Bool), nil
		}
		return cty.True, nil
	},
})

var AnyTrueFunc = function.New(&function.Spec{
	Params: []function.Parameter{{
		Name: "list",
		Type: cty.List(cty.Bool),
	}},
	Type: function.StaticReturnType(cty.Bool),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		result := cty.False
		hasUnknown := false
		for it := args[0].ElementIterator(); it.Next(); {
			_, v := it.Element()
			if !v.IsKnown() {
				hasUnknown = true
				continue
			}
			if v.IsNull() {
				continue
			}
			result = result.Or(v)
			if result.True() {
				return cty.True, nil
			}
		}
		if hasUnknown {
			return cty.UnknownVal(cty.Bool), nil
		}
		return result, nil
	},
})

var SumFunc = function.New(&function.Spec{
	Params: []function.Parameter{{
		Name: "list",
		Type: cty.DynamicPseudoType,
	}},
	Type: function.StaticReturnType(cty.Number),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		list := args[0]
		ty := list.Type()
		if !ty.IsListType() && !ty.IsSetType() && !ty.IsTupleType() {
			return cty.NilVal, function.NewArgErrorf(0, "argument must be list, set, or tuple")
		}
		if !list.IsWhollyKnown() {
			return cty.UnknownVal(cty.Number), nil
		}
		if list.LengthInt() == 0 {
			return cty.NilVal, function.NewArgErrorf(0, "cannot sum an empty list")
		}
		elems := list.AsValueSlice()
		total, err := ctyconvert.Convert(elems[0], cty.Number)
		if err != nil || total.IsNull() {
			return cty.NilVal, function.NewArgErrorf(0, "argument must be list, set, or tuple of number values")
		}
		for _, elem := range elems[1:] {
			n, convErr := ctyconvert.Convert(elem, cty.Number)
			if convErr != nil || n.IsNull() {
				return cty.NilVal, function.NewArgErrorf(0, "argument must be list, set, or tuple of number values")
			}
			total = total.Add(n)
		}
		return total, nil
	},
})

var OneFunc = function.New(&function.Spec{
	Params: []function.Parameter{{
		Name: "list",
		Type: cty.DynamicPseudoType,
	}},
	Type: func(args []cty.Value) (cty.Type, error) {
		ty := args[0].Type()
		switch {
		case ty.IsListType(), ty.IsSetType():
			return ty.ElementType(), nil
		case ty.IsTupleType():
			etys := ty.TupleElementTypes()
			switch len(etys) {
			case 0:
				return cty.DynamicPseudoType, nil
			case 1:
				return etys[0], nil
			}
		}
		return cty.NilType, function.NewArgErrorf(0, "must be a list, set, or tuple value with either zero or one elements")
	},
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		val := args[0]
		if !val.IsKnown() {
			return cty.UnknownVal(retType), nil
		}
		length := val.Length()
		if !length.IsKnown() {
			return cty.UnknownVal(retType), nil
		}
		var n int
		if err := gocty.FromCtyValue(length, &n); err != nil {
			return cty.NilVal, err
		}
		switch n {
		case 0:
			return cty.NullVal(retType), nil
		case 1:
			for it := val.ElementIterator(); it.Next(); {
				_, elem := it.Element()
				return elem, nil
			}
		}
		return cty.NilVal, function.NewArgErrorf(0, "must be a list, set, or tuple value with either zero or one elements")
	},
})

var MatchkeysFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "values", Type: cty.List(cty.DynamicPseudoType)},
		{Name: "keys", Type: cty.List(cty.DynamicPseudoType)},
		{Name: "searchset", Type: cty.List(cty.DynamicPseudoType)},
	},
	Type: func(args []cty.Value) (cty.Type, error) {
		if ty, _ := ctyconvert.UnifyUnsafe([]cty.Type{args[1].Type(), args[2].Type()}); ty == cty.NilType {
			return cty.NilType, errors.New("keys and searchset must be of the same type")
		}
		return args[0].Type(), nil
	},
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		values, keys, searchset := args[0], args[1], args[2]
		if !values.IsKnown() || !keys.IsKnown() || !searchset.IsKnown() {
			return cty.UnknownVal(retType), nil
		}
		if values.LengthInt() != keys.LengthInt() {
			return cty.NilVal, errors.New("length of keys and values should be equal")
		}
		if searchset.LengthInt() == 0 {
			return cty.ListValEmpty(retType.ElementType()), nil
		}
		if !values.IsWhollyKnown() || !keys.IsWhollyKnown() {
			return cty.UnknownVal(retType), nil
		}
		var out []cty.Value
		i := 0
		for it := keys.ElementIterator(); it.Next(); {
			_, key := it.Element()
			for sit := searchset.ElementIterator(); sit.Next(); {
				_, search := sit.Element()
				eq, err := stdlib.Equal(key, search)
				if err != nil {
					return cty.NilVal, err
				}
				if !eq.IsKnown() {
					return cty.UnknownVal(retType), nil
				}
				if eq.True() {
					out = append(out, values.Index(cty.NumberIntVal(int64(i))))
					break
				}
			}
			i++
		}
		if len(out) == 0 {
			return cty.ListValEmpty(retType.ElementType()), nil
		}
		return cty.ListVal(out), nil
	},
})

var TransposeFunc = function.New(&function.Spec{
	Params: []function.Parameter{{
		Name: "values",
		Type: cty.Map(cty.List(cty.String)),
	}},
	Type: function.StaticReturnType(cty.Map(cty.List(cty.String))),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		input := args[0]
		if !input.IsWhollyKnown() {
			return cty.UnknownVal(retType), nil
		}
		tmp := make(map[string][]string)
		for it := input.ElementIterator(); it.Next(); {
			inKey, inVal := it.Element()
			if inVal.IsNull() {
				return cty.NilVal, errors.New("input must not contain null list")
			}
			for vit := inVal.ElementIterator(); vit.Next(); {
				_, val := vit.Element()
				if val.IsNull() {
					return cty.NilVal, errors.New("input list must not contain null string")
				}
				outKey := val.AsString()
				tmp[outKey] = append(tmp[outKey], inKey.AsString())
			}
		}
		if len(tmp) == 0 {
			return cty.MapValEmpty(cty.List(cty.String)), nil
		}
		out := make(map[string]cty.Value, len(tmp))
		for k, vs := range tmp {
			sort.Strings(vs)
			elems := make([]cty.Value, len(vs))
			for i, v := range vs {
				elems[i] = cty.StringVal(v)
			}
			out[k] = cty.ListVal(elems)
		}
		return cty.MapVal(out), nil
	},
})
