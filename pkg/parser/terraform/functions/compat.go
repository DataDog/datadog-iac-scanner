/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"errors"
	"fmt"
	"strings"

	"github.com/zclconf/go-cty/cty"
	ctyconvert "github.com/zclconf/go-cty/cty/convert"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

// CoalesceFunc matches Terraform: first non-null, non-empty-string argument.
var CoalesceFunc = function.New(&function.Spec{
	Params: []function.Parameter{},
	VarParam: &function.Parameter{
		Name:             "vals",
		Type:             cty.DynamicPseudoType,
		AllowUnknown:     true,
		AllowDynamicType: true,
		AllowNull:        true,
	},
	Type: func(args []cty.Value) (cty.Type, error) {
		argTypes := make([]cty.Type, len(args))
		for i, val := range args {
			argTypes[i] = val.Type()
		}
		retType, _ := ctyconvert.UnifyUnsafe(argTypes)
		if retType == cty.NilType {
			return cty.NilType, errors.New("all arguments must have the same type")
		}
		return retType, nil
	},
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		for _, argVal := range args {
			converted, err := ctyconvert.Convert(argVal, retType)
			if err != nil {
				return cty.NilVal, err
			}
			if !converted.IsKnown() {
				return cty.UnknownVal(retType), nil
			}
			if converted.IsNull() {
				continue
			}
			if retType == cty.String && converted.RawEquals(cty.StringVal("")) {
				continue
			}
			return converted, nil
		}
		return cty.NilVal, errors.New("no non-null, non-empty-string arguments")
	},
})

// LengthFunc matches Terraform: strings, collections, and objects.
var LengthFunc = function.New(&function.Spec{
	Params: []function.Parameter{{
		Name:             "value",
		Type:             cty.DynamicPseudoType,
		AllowDynamicType: true,
		AllowUnknown:     true,
		AllowMarked:      true,
	}},
	Type: function.StaticReturnType(cty.Number),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		val := args[0]
		ty := val.Type()
		switch {
		case ty == cty.String:
			return stdlib.Strlen(val)
		case ty.IsObjectType():
			if !val.IsKnown() {
				return cty.UnknownVal(cty.Number), nil
			}
			return cty.NumberIntVal(int64(len(ty.AttributeTypes()))), nil
		default:
			return stdlib.Length(val)
		}
	},
})

// LookupFunc matches Terraform: optional default, maps and objects.
var LookupFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{
			Name:         "inputMap",
			Type:         cty.DynamicPseudoType,
			AllowMarked:  true,
			AllowUnknown: true,
		},
		{
			Name:         "key",
			Type:         cty.String,
			AllowMarked:  true,
			AllowUnknown: true,
		},
	},
	VarParam: &function.Parameter{
		Name:             "default",
		Type:             cty.DynamicPseudoType,
		AllowUnknown:     true,
		AllowDynamicType: true,
		AllowNull:        true,
		AllowMarked:      true,
	},
	Type: func(args []cty.Value) (cty.Type, error) {
		if len(args) > 3 {
			return cty.NilType, fmt.Errorf("lookup() takes two or three arguments, got %d", len(args))
		}
		ty := args[0].Type()
		switch {
		case ty.IsObjectType():
			if !args[1].IsKnown() {
				return cty.DynamicPseudoType, nil
			}
			keyVal, _ := args[1].Unmark()
			key := keyVal.AsString()
			if ty.HasAttribute(key) {
				return args[0].GetAttr(key).Type(), nil
			}
			if len(args) == 3 {
				return args[2].Type(), nil
			}
			return cty.DynamicPseudoType, function.NewArgErrorf(0, "the given object has no attribute %q", key)
		case ty.IsMapType():
			if len(args) == 3 {
				if _, err := ctyconvert.Convert(args[2], ty.ElementType()); err != nil {
					return cty.NilType, function.NewArgErrorf(2, "the default value must have the same type as the map elements")
				}
			}
			return ty.ElementType(), nil
		default:
			return cty.NilType, function.NewArgErrorf(0, "lookup() requires a map as the first argument")
		}
	},
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		mapVar, mapMarks := args[0].Unmark()
		keyVal, keyMarks := args[1].Unmark()

		if !mapVar.IsKnown() || !keyVal.IsKnown() {
			return cty.UnknownVal(retType).WithMarks(mapMarks, keyMarks), nil
		}

		lookupKey := keyVal.AsString()
		found := cty.NilVal
		switch {
		case mapVar.Type().IsObjectType() && mapVar.Type().HasAttribute(lookupKey):
			found = mapVar.GetAttr(lookupKey)
		case mapVar.Type().IsMapType() && mapVar.HasIndex(cty.StringVal(lookupKey)) == cty.True:
			found = mapVar.Index(cty.StringVal(lookupKey))
		}
		if found != cty.NilVal {
			return found.WithMarks(mapMarks, keyMarks), nil
		}
		if len(args) == 3 {
			defaultVal, err := ctyconvert.Convert(args[2], retType)
			if err != nil {
				return cty.NilVal, err
			}
			return defaultVal.WithMarks(mapMarks, keyMarks), nil
		}
		return cty.NilVal, fmt.Errorf("lookup failed to find key %s", lookupKey)
	},
})

// IndexFunc matches Terraform: first index of value in a list or tuple.
var IndexFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "list", Type: cty.DynamicPseudoType},
		{Name: "value", Type: cty.DynamicPseudoType},
	},
	Type: function.StaticReturnType(cty.Number),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		list := args[0]
		if !list.Type().IsListType() && !list.Type().IsTupleType() {
			return cty.NilVal, errors.New("argument must be a list or tuple")
		}
		if !list.IsKnown() {
			return cty.UnknownVal(cty.Number), nil
		}
		if list.LengthInt() == 0 {
			return cty.NilVal, errors.New("cannot search an empty list")
		}
		for it := list.ElementIterator(); it.Next(); {
			i, v := it.Element()
			eq, err := stdlib.Equal(v, args[1])
			if err != nil {
				return cty.NilVal, err
			}
			if !eq.IsKnown() {
				return cty.UnknownVal(cty.Number), nil
			}
			if eq.True() {
				return i, nil
			}
		}
		return cty.NilVal, errors.New("item not found")
	},
})

// ReplaceFunc matches Terraform: /pattern/ is a regular expression.
var ReplaceFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "str", Type: cty.String},
		{Name: "substr", Type: cty.String},
		{Name: "replace", Type: cty.String},
	},
	Type: function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		substr := args[1].AsString()
		if len(substr) > 1 && strings.HasPrefix(substr, "/") && strings.HasSuffix(substr, "/") {
			pattern := cty.StringVal(substr[1 : len(substr)-1])
			return stdlib.RegexReplace(args[0], pattern, args[2])
		}
		return stdlib.Replace(args[0], args[1], args[2])
	},
})
