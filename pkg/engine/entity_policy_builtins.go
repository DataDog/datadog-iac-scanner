/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/DataDog/datadog-iac-scanner/pkg/policy"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/open-policy-agent/opa/v1/types"
)

var errSymbolicRead = errors.New("policy read requires symbolic evaluation")

type entitySessionKey struct{}
type entityReadKey struct{ subject, path string }
type entityReadFact struct {
	read       policy.Read
	symbol     string
	presence   string
	descriptor *ast.Term
}
type entityCachedPath struct {
	array   *ast.Array
	cost    int
	path    policy.Path
	encoded string
}

type entitySession struct {
	reader       policy.Reader
	targets      map[entitySelector]*ast.Term
	facts        map[entityReadKey]*entityReadFact
	totalSymbols map[string]struct{}
	paths        map[int]entityCachedPath
	factBytes    int
	pathBytes    int
	symbolic     bool
	failure      error
	discovered   map[entityDiscoveryUnit]bool
}

func entitySessionFrom(ctx context.Context) (*entitySession, error) {
	s, ok := ctx.Value(entitySessionKey{}).(*entitySession)
	if !ok {
		return nil, errors.New("entity evaluation session missing")
	}
	return s, nil
}
func entityPath(term *ast.Term) (policy.Path, error) {
	array, ok := term.Value.(*ast.Array)
	if !ok {
		return nil, fmt.Errorf("entity path must be an array")
	}
	path := make(policy.Path, array.Len())
	for i := range array.Len() {
		switch v := array.Elem(i).Value.(type) {
		case ast.String:
			path[i] = policy.Key(string(v))
		case ast.Number:
			n, err := entityIndex(string(v))
			if err != nil {
				return nil, fmt.Errorf("entity path index must be an integer: %s", v)
			}
			path[i] = policy.Index(n)
		default:
			return nil, fmt.Errorf("entity path steps must be property names or integer indexes")
		}
	}
	return path, nil
}
func (s *entitySession) fact(subjectTerm, pathTerm *ast.Term) (*entityReadFact, error) {
	subject, ok := subjectTerm.Value.(ast.String)
	if !ok {
		return nil, fmt.Errorf("entity identity must be a string")
	}
	parsed, err := s.path(pathTerm)
	if err != nil {
		return nil, err
	}
	key := entityReadKey{string(subject), parsed.encoded}
	if fact, ok := s.facts[key]; ok {
		return fact, nil
	}
	read, err := s.read(key.subject, parsed.path)
	if err != nil {
		return nil, err
	}
	symbol, presence := "", ""
	if read.State == policy.Unknown || read.MaybeAbsent {
		raw, _ := json.Marshal([]string{key.subject, key.path})
		presence = "path:" + string(raw)
		symbol = presence
		if read.Symbol != "" {
			symbol = "origin:" + read.Symbol
		}
	}
	// Required unknown values are total, including null. Presence of another
	// observation remains independent even when its value origin is shared.
	if read.State == policy.Unknown && !read.MaybeAbsent {
		if s.totalSymbols == nil {
			s.totalSymbols = map[string]struct{}{}
		}
		s.totalSymbols[symbol] = struct{}{}
	}
	// An origin identifies a value, not the presence of every attribute that
	// might hold it. Presence remains tied to this observation's subject/path.
	fact := &entityReadFact{read: read, symbol: symbol, presence: presence}
	// Per-evaluation cache, bounded by observations, never by all source values.
	// Eviction cannot change a symbol: identities are derived from the read key.
	cost := len(key.subject) + len(key.path) + len(symbol) + len(presence) + entityScalarBytes(read.Value)
	if cost <= maxEntityCachedFactBytes {
		if len(s.facts) >= entityReadCacheEntries || s.factBytes+cost > maxEntityCachedFactBytes {
			clear(s.facts)
			s.factBytes = 0
		}
		if s.facts == nil {
			s.facts = map[entityReadKey]*entityReadFact{}
		}
		s.facts[key] = fact
		s.factBytes += cost
	}
	return fact, nil
}

// read validates the adapter boundary and preserves real failures independently
// from the sentinel used to request symbolic execution. Native reads retain no
// per-value facts; the symbolic path alone caches repeated observations.
func (s *entitySession) read(subject string, path policy.Path) (policy.Read, error) {
	read, err := s.reader.Read(subject, path)
	if err == nil {
		err = validateEntityRead(read)
	}
	if err != nil {
		s.failure = err
	}
	return read, err
}
func (s *entitySession) path(term *ast.Term) (entityCachedPath, error) {
	array, ok := term.Value.(*ast.Array)
	if !ok {
		return entityCachedPath{}, fmt.Errorf("entity path must be an array")
	}
	hash := array.Hash()
	if cached, ok := s.paths[hash]; ok && cached.array.Compare(array) == 0 {
		return cached, nil
	}
	path, err := entityPath(term)
	if err != nil {
		return entityCachedPath{}, err
	}
	encoded, err := json.Marshal(path)
	if err != nil {
		return entityCachedPath{}, err
	}
	if s.paths == nil {
		s.paths = map[int]entityCachedPath{}
	}

	cached := entityCachedPath{array: array, path: path, encoded: string(encoded)}
	cost := len(encoded) + len(path)*entityCachedStepBytes
	if cost <= maxEntityCachedPathBytes {
		if old, ok := s.paths[hash]; ok {
			s.pathBytes -= old.cost
		}
		if len(s.paths) >= maxEntityCachedPaths || s.pathBytes+cost > maxEntityCachedPathBytes {
			clear(s.paths)
			s.pathBytes = 0
		}
		cached.cost = cost
		s.paths[hash] = cached
		s.pathBytes += cost
	}
	return cached, nil
}
func entityIndex(text string) (int64, error) {
	if n, err := strconv.ParseInt(text, 10, 64); err == nil {
		return n, nil
	}
	rational, ok := new(big.Rat).SetString(text)
	if !ok || !rational.IsInt() || !rational.Num().IsInt64() {
		return 0, fmt.Errorf("entity path index must be an integer: %s", text)
	}
	return rational.Num().Int64(), nil
}

func entityScalarBytes(value any) int {
	switch v := value.(type) {
	case string:
		return len(v)
	case json.Number:
		return len(v)
	default:
		return 0
	}
}

func validateEntityRead(r policy.Read) error {
	switch r.State {
	case policy.Absent:
		if r.MaybeAbsent || r.NonNull || r.Value != nil {
			return errors.New("invalid absent entity read")
		}
	case policy.Null:
		if r.NonNull || r.Value != nil {
			return errors.New("invalid null entity read")
		}
	case policy.Known:
		switch r.Value.(type) {
		case string, bool, json.Number:
		default:
			return &policy.Unsupported{Operation: "non-scalar or untyped known policy read"}
		}
	case policy.Unknown:
		if r.Value != nil {
			return errors.New("unknown entity read contains a concrete value")
		}
	default:
		return errors.New("entity read has no authoritative state")
	}
	return nil
}

type entityFunction struct {
	definition *rego.Function
	invoke     rego.BuiltinDyn
}

const (
	entityReadCacheEntries   = 4096
	maxEntityCachedFactBytes = 2 << 20
	maxEntityCachedPathBytes = 256 << 10
	entityCachedStepBytes    = 64
	maxEntityCachedPaths     = 64
	entityReadRaw            = "raw"
	entityReadPresent        = "present"
	entityReadNonNull        = "nonnull"
)

func entityFunctions() []entityFunction {
	pathType := types.NewArray(nil, types.NewAny(types.S, types.N))
	describe := &rego.Function{Name: "dd.describe", Decl: types.NewFunction(types.Args(types.S, pathType), types.A)}
	functions := []entityFunction{
		newEntityTargetsFunction(),
		entityInventoryFunction(),
		{describe, func(b rego.BuiltinContext, args []*ast.Term) (*ast.Term, error) {
			id, path := args[0], args[1]
			s, err := entitySessionFrom(b.Context)
			if err != nil {
				return nil, err
			}
			f, err := s.fact(id, path)
			if err != nil {
				return nil, err
			}
			if f.descriptor != nil {
				return f.descriptor, nil
			}
			r := f.read
			state := "known"
			if r.State == policy.Absent {
				state = "absent"
			}
			if r.State == policy.Unknown {
				state = "unknown"
			}
			value, err := ast.InterfaceToValue(map[string]any{
				"state": state, "value": r.Value, "maybe_absent": r.MaybeAbsent,
				"non_null": r.NonNull, "symbol": f.symbol, "presence_symbol": f.presence,
			})
			if err != nil {
				return nil, err
			}
			f.descriptor = ast.NewTerm(value)
			return f.descriptor, nil
		}},
	}
	for _, operation := range []string{entityReadRaw, entityReadPresent, entityReadNonNull} {
		resultType := types.A
		if operation != entityReadRaw {
			resultType = types.B
		}
		definition := &rego.Function{
			Name: "dd.native_" + operation, Decl: types.NewFunction(types.Args(types.S, pathType, types.A, types.B), resultType),
		}
		functions = append(functions, entityFunction{definition, nativeEntityBuiltin(operation)})
	}
	return functions
}

// Focus affects only the primary driver and is part of its memoization key.
func newEntityTargetsFunction() entityFunction {
	definition := &rego.Function{
		Name: "dd.targets", Decl: types.NewFunction(types.Args(types.S, types.S, types.A), types.NewArray(nil, types.S)), Memoize: true,
	}
	return entityFunction{definition, func(b rego.BuiltinContext, args []*ast.Term) (*ast.Term, error) {
		kind, typ := args[0], args[1]
		s, err := entitySessionFrom(b.Context)
		if err != nil {
			return nil, err
		}
		targets, ok := s.targets[entitySelector{string(kind.Value.(ast.String)), string(typ.Value.(ast.String))}]
		if !ok {
			return nil, errors.New("primary target selector does not match the execution plan")
		}
		if !args[2].Equal(ast.NullTerm()) {
			unit, err := entityDiscoveryFocus(args[2])
			if err != nil {
				return nil, err
			}
			return ast.ArrayTerm(ast.StringTerm(unit.subject)), nil
		}
		return targets, nil
	}}
}

// Related inventories always use the full immutable Reader.
func entityInventoryFunction() entityFunction {
	definition := &rego.Function{
		Name: "dd.entities", Decl: types.NewFunction(types.Args(types.S, types.S), types.NewArray(nil, types.S)), Memoize: true,
	}
	return entityFunction{definition, func(b rego.BuiltinContext, args []*ast.Term) (*ast.Term, error) {
		kind, typ := args[0], args[1]
		s, err := entitySessionFrom(b.Context)
		if err != nil {
			return nil, err
		}
		ids, err := s.reader.Entities(string(kind.Value.(ast.String)), string(typ.Value.(ast.String)))
		if err != nil {
			s.failure = err
			return nil, err
		}
		terms := make([]*ast.Term, len(ids))
		for i, id := range ids {
			terms[i] = ast.StringTerm(id)
		}
		return ast.ArrayTerm(terms...), nil
	}}
}
func nativeEntityBuiltin(operation string) rego.BuiltinDyn {
	return func(b rego.BuiltinContext, args []*ast.Term) (*ast.Term, error) {
		id, path := args[0], args[1]
		s, err := entitySessionFrom(b.Context)
		if err != nil {
			return nil, err
		}
		parsed, err := s.path(path)
		if err != nil {
			return nil, err
		}
		read, err := s.read(string(id.Value.(ast.String)), parsed.path)
		if err != nil {
			return nil, err
		}
		if nativeEntityUncertain(read, operation) {
			if args[3].Equal(ast.BooleanTerm(true)) {
				if s.discovered == nil {
					return nil, errors.New("discovery session missing")
				}
				unit, err := entityDiscoveryFocus(args[2])
				if err != nil {
					return nil, err
				}
				s.discovered[unit] = true
				return nil, nil
			}
			s.symbolic = true
			return nil, errSymbolicRead
		}
		return nativeEntityValue(read, operation)
	}
}
func nativeEntityUncertain(r policy.Read, operation string) bool {
	return r.MaybeAbsent || (r.State == policy.Unknown && operation == entityReadRaw) ||
		(r.State == policy.Unknown && operation == entityReadNonNull && !r.NonNull)
}
func nativeEntityValue(r policy.Read, operation string) (*ast.Term, error) {
	switch operation {
	case entityReadPresent:
		return ast.BooleanTerm(r.State != policy.Absent), nil
	case entityReadNonNull:
		return ast.BooleanTerm(r.State == policy.Known || (r.State == policy.Unknown && r.NonNull)), nil
	default:
		if r.State == policy.Absent {
			return nil, nil
		}
		v, err := ast.InterfaceToValue(r.Value)
		if err != nil {
			return nil, err
		}
		return ast.NewTerm(v), nil
	}
}

// Native residuals use the same implementations as prepared Rego queries.
// The adaptation preserves undefined results, errors, and per-query memoization.
type entityBuiltinMemoKey string
type entityBuiltinMemo struct {
	value *ast.Term
	err   error
}

func entityTopdownBuiltins(functions []entityFunction) map[string]*topdown.Builtin {
	result := make(map[string]*topdown.Builtin, len(functions))
	for _, f := range functions {
		definition, invoke := f.definition, f.invoke
		declaration := &ast.Builtin{Name: definition.Name, Decl: definition.Decl, Nondeterministic: definition.Nondeterministic}
		result[definition.Name] = &topdown.Builtin{Decl: declaration, Func: func(
			b topdown.BuiltinContext, terms []*ast.Term, iter func(*ast.Term) error,
		) error {
			var value *ast.Term
			var err error
			if definition.Memoize {
				key := entityBuiltinMemoKey(definition.Name + ast.NewArray(terms[:definition.Decl.Arity()]...).String())
				if cached, ok := b.Cache.Get(key); ok {
					m := cached.(entityBuiltinMemo)
					value, err = m.value, m.err
				} else {
					value, err = invoke(b, terms)
					b.Cache.Put(key, entityBuiltinMemo{value, err})
				}
			} else {
				value, err = invoke(b, terms)
			}
			if err != nil {
				return (&topdown.Error{Code: topdown.BuiltinErr, Message: definition.Name + ": " + err.Error(), Location: b.Location}).Wrap(err)
			}
			if value == nil {
				return nil
			}
			return iter(value)
		}}
	}
	return result
}

const entityLibrary = `package iac

import rego.v1

entities(kind, typ) := dd.entities(kind, typ)
targets(kind, typ) := dd.targets(kind, typ, input.__dd_focus)
finding(entity, path, details) := object.union(details, {"_dd_id": entity, "path": path})
raw(entity, path) := dd.native_raw(entity, path, input.__dd_focus, input.__dd_discovery) if input.__dd_mode == "native"

raw(entity, path) := d.value if {
	input.__dd_mode == "symbolic"
	d := dd.describe(entity, path)
	d.state == "known"
	_present(entity, path)
}

raw(entity, path) := v if {
	input.__dd_mode == "symbolic"
	d := dd.describe(entity, path)
	d.state == "unknown"
	_present(entity, path)
	v := input.__dd_symbols.values[d.symbol]
	_value_shape(d, v)
}

_value_shape(d, v) if not d.non_null

_value_shape(d, v) if {
	d.non_null
	v != null
}

_present(entity, path) if {
	d := dd.describe(entity, path)
	d.state != "absent"
	not d.maybe_absent
}

_present(entity, path) if {
	d := dd.describe(entity, path)
	d.state != "absent"
	d.maybe_absent
	input.__dd_symbols.presence[d.presence_symbol] == true
}

present(entity, path) if {
	input.__dd_mode == "native"
	dd.native_present(entity, path, input.__dd_focus, input.__dd_discovery) == true
}

present(entity, path) if {
	input.__dd_mode == "symbolic"
	_present(entity, path)
}

present_value(entity, path) if present(entity, path)
present_value(entity, path) := false if not present(entity, path)

_nonnull(entity, path) if {
	d := dd.describe(entity, path)
	d.state == "unknown"
	d.non_null
	_present(entity, path)
}

_nonnull(entity, path) if {
	v := raw(entity, path)
	v != null
}

nonnull(entity, path) if {
	input.__dd_mode == "native"
	dd.native_nonnull(entity, path, input.__dd_focus, input.__dd_discovery) == true
}

nonnull(entity, path) if {
	input.__dd_mode == "symbolic"
	_nonnull(entity, path)
}

valid_key(entity, path) if nonnull(entity, path)
valid_key(entity, path) := false if not nonnull(entity, path)

value(entity, path) := v if {
	v := raw(entity, path)
	v != null
}
`
