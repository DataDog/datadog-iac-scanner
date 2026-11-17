/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package schedule

import (
	"context"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/topdown"
)

// Builtins that only test the shape of their operand. Restricting the input
// to the harvested types keeps every object an object.
var shapeBuiltins = map[string]bool{
	"is_object": true, "is_array": true, "is_string": true, "is_number": true,
	"is_boolean": true, "is_null": true, "is_set": true, "type_name": true,
}

// combineMode says which parts of its operands a collection builtin returns.
type combineMode int

const (
	// combineElems: elements of every operand.
	combineElems combineMode = iota
	// combineFirst: elements of the first operand.
	combineFirst
	// combineNested: elements of the elements of the first operand.
	combineNested
	// combineKeys: keys of the first operand.
	combineKeys
)

// Builtins whose result holds only elements (or keys) of their operands.
var elementBuiltins = map[string]combineMode{
	"or": combineElems, "and": combineFirst, "minus": combineFirst, "intersection": combineNested,
	"union": combineNested, "array.concat": combineElems, "array.slice": combineFirst,
	"array.reverse": combineFirst, "sort": combineFirst, "object.remove": combineFirst,
	"object.filter": combineFirst, "object.union": combineElems, "object.union_n": combineNested,
	"object.keys": combineKeys,
}

// Pure builtins folded when every operand is a known constant, so a type
// built from constants (sprintf("aws_%s", ["lb"])) stays a constant. Every
// element builtin is folded too.
var foldBuiltins = withElementBuiltins(map[string]bool{
	"concat": true, "sprintf": true, "lower": true, "upper": true, "trim": true,
	"trim_prefix": true, "trim_suffix": true, "trim_left": true, "trim_right": true,
	"trim_space": true, "replace": true, "split": true, "substring": true,
	"format_int": true, "json.unmarshal": true, "to_number": true,
})

func withElementBuiltins(names map[string]bool) map[string]bool {
	for name := range elementBuiltins {
		names[name] = true
	}
	return names
}

func (f *frame) builtin(name string, args []*ast.Term) absVal {
	if name == "object.get" && len(args) == 3 {
		return f.objectGet(args)
	}
	vals := make([]absVal, len(args))
	for i, a := range args {
		vals[i] = f.evalTerm(a)
	}
	if shapeBuiltins[name] {
		return topVal
	}
	if ast.BuiltinMap[name] == nil {
		f.dynf("calls unknown builtin %s", name)
	}
	for _, v := range vals {
		f.consume(v)
	}
	if out, ok := fold(name, vals); ok {
		return out
	}
	if how, ok := elementBuiltins[name]; ok {
		return combine(how, vals)
	}
	return topVal
}

func fold(name string, vals []absVal) (absVal, bool) {
	if !foldBuiltins[name] {
		return absVal{}, false
	}
	bf := topdown.GetBuiltin(name)
	if bf == nil {
		return absVal{}, false
	}
	var combos [][]*ast.Term
	if _, ok := product(vals, func(ts []*ast.Term) *ast.Term {
		combos = append(combos, ts)
		return nil
	}); !ok {
		return absVal{}, false
	}
	var out []*ast.Term
	for _, operands := range combos {
		res, ok := callBuiltin(bf, operands)
		if !ok {
			return absVal{}, false
		}
		out = append(out, res...)
	}
	return constVal(out...), true
}

func callBuiltin(bf topdown.BuiltinFunc, operands []*ast.Term) (out []*ast.Term, ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	err := bf(topdown.BuiltinContext{Context: context.Background()}, operands, func(t *ast.Term) error {
		out = append(out, t)
		return nil
	})
	return out, err == nil
}

// combine over-approximates a collection builtin by the elements of its
// operands.
func combine(how combineMode, vals []absVal) absVal {
	if len(vals) == 0 {
		return topVal
	}
	switch how {
	case combineFirst:
		keys, elems := elementsOf(vals[0])
		return collVal(keys, elems)
	case combineKeys:
		keys, _ := elementsOf(vals[0])
		return collVal(keys, keys)
	case combineNested:
		_, outer := elementsOf(vals[0])
		keys, elems := elementsOf(outer)
		return collVal(keys, elems)
	default:
		var ks, es []absVal
		for _, v := range vals {
			k, e := elementsOf(v)
			ks, es = append(ks, k), append(es, e)
		}
		return collVal(union(ks...), union(es...))
	}
}

// elementsOf lists keys and elements without reading input paths, which the
// caller has already consumed.
// nolint:gocritic
func elementsOf(v absVal) (keys, elems absVal) {
	var ks, es []absVal
	if v.top || len(v.paths) > 0 {
		ks, es = append(ks, topVal), append(es, topVal)
	}
	for _, c := range v.consts {
		k, e := constKeysAndElems(c)
		ks, es = append(ks, constVal(k...)), append(es, constVal(e...))
	}
	for _, c := range v.colls {
		ks, es = append(ks, c.keys), append(es, c.elems)
	}
	return union(ks...), union(es...)
}
