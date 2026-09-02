package functions

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"
	ctyconvert "github.com/zclconf/go-cty/cty/convert"
	"github.com/zclconf/go-cty/cty/function"
)

const (
	collectionKindSet  = "set"
	collectionKindList = "list"
	collectionKindMap  = "map"
)

var (
	// ToSetFunc - https://developer.hashicorp.com/terraform/language/functions/toset
	ToSetFunc = collectionConvertFunc(collectionKindSet)
	// ToListFunc - https://developer.hashicorp.com/terraform/language/functions/tolist
	ToListFunc = collectionConvertFunc(collectionKindList)
	// ToMapFunc - https://developer.hashicorp.com/terraform/language/functions/tomap
	ToMapFunc = collectionConvertFunc(collectionKindMap)
)

func collectionConvertFunc(kind string) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{{
			Name:             "input",
			Type:             cty.DynamicPseudoType,
			AllowDynamicType: true,
			AllowNull:        true,
		}},
		Type: function.StaticReturnType(cty.DynamicPseudoType),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			arg := args[0]
			if arg.IsNull() {
				return cty.NullVal(cty.DynamicPseudoType), nil
			}
			if !arg.IsWhollyKnown() {
				return cty.UnknownVal(cty.DynamicPseudoType), nil
			}

			outTy, err := collectionTargetType(arg, kind)
			if err != nil {
				return cty.NilVal, function.NewArgError(0, err)
			}
			return ctyconvert.Convert(arg, outTy)
		},
	})
}

func collectionTargetType(val cty.Value, kind string) (cty.Type, error) {
	switch kind {
	case collectionKindSet, collectionKindList:
		elemTy, err := sequenceElementType(val)
		if err != nil {
			return cty.NilType, err
		}
		if kind == collectionKindSet {
			return cty.Set(elemTy), nil
		}
		return cty.List(elemTy), nil
	case collectionKindMap:
		elemTy, err := mapElementType(val)
		if err != nil {
			return cty.NilType, err
		}
		return cty.Map(elemTy), nil
	default:
		return cty.NilType, fmt.Errorf("unsupported collection conversion %q", kind)
	}
}

func mapElementType(val cty.Value) (cty.Type, error) {
	ty := val.Type()
	if ty.IsMapType() {
		return ty.ElementType(), nil
	}
	if ty.IsObjectType() {
		attrTypes := ty.AttributeTypes()
		if len(attrTypes) == 0 {
			return cty.DynamicPseudoType, nil
		}
		var elemTy cty.Type
		for _, attrTy := range attrTypes {
			if elemTy == cty.NilType {
				elemTy = attrTy
				continue
			}
			if !attrTy.Equals(elemTy) {
				return cty.DynamicPseudoType, nil
			}
		}
		return elemTy, nil
	}
	return cty.NilType, fmt.Errorf("cannot convert %s to map", ty.FriendlyName())
}

func sequenceElementType(val cty.Value) (cty.Type, error) {
	ty := val.Type()
	switch {
	case ty.IsListType(), ty.IsSetType():
		return ty.ElementType(), nil
	case ty.IsTupleType():
		elemTypes := ty.TupleElementTypes()
		if len(elemTypes) == 0 {
			return cty.DynamicPseudoType, nil
		}
		elemTy := elemTypes[0]
		for _, candidate := range elemTypes[1:] {
			if !candidate.Equals(elemTy) {
				return cty.DynamicPseudoType, nil
			}
		}
		return elemTy, nil
	default:
		return cty.NilType, fmt.Errorf("cannot convert %s to a sequence collection", ty.FriendlyName())
	}
}
