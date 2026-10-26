/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"strconv"

	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/partial"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// The roots a shareable local may read.
const (
	rootVar       = "var"
	rootLocal     = "local"
	rootPath      = "path"
	rootTerraform = "terraform"
)

// localMemoCap bounds the local values shared across module instances.
const localMemoCap = 1024

// localMemoKey identifies a local's value by its expression and the values it
// reads. The expression pins the module directory its functions resolve files
// against, and the values read include path.*, which pins the root.
type localMemoKey struct {
	expr   hclsyntax.Expression
	inputs inputsDigest
}

// localReads is what a local expression reads. It is shareable when it reads
// nothing but var.*, local.*, path.* and terraform.*, so that its value is a
// function of those alone.
type localReads struct {
	shareable bool
	refs      []hcl.Traversal
}

// pendingLocal is one evaluation of an expression that has not been seen from
// another instance with the same inputs. A second instance promotes it into
// localMemo. The same instance, including its prepass and its main pass, does
// not: that is one evaluation, and the inputs are not hashed until a second
// instance exists. key is the digest of inputs once one was computed.
type pendingLocal struct {
	addr   string
	inputs map[string]cty.Value
	keyed  bool
	key    inputsDigest
	value  cty.Value
}

// localValue evaluates a local, sharing the value with every evaluation of the
// same expression that reads the same values.
//
// A module loop hands every instance the same configuration, and a local
// derived from it alone is the same in each instance. The value is kept after
// a second instance reads the same inputs. A value that changes with the
// instance is evaluated and dropped, and the inputs are hashed only once a
// second instance makes a hit possible.
func (e *Evaluator) localValue(expr hclsyntax.Expression, ctx *hcl.EvalContext) cty.Value {
	reads := e.localReadsOf(expr)
	if !reads.shareable {
		return evalLocal(expr, ctx)
	}
	inputs, ok := localInputs(reads.refs, ctx)
	if !ok {
		return evalLocal(expr, ctx)
	}
	v, hit, next := e.reuseLocal(expr, inputs)
	if hit {
		return v
	}
	next.value = evalLocal(expr, ctx)
	e.rememberLocal(expr, &next)
	return next.value
}

// reuseLocal returns a local already evaluated for these inputs. The same
// instance reuses its pending value without hashing. An expression already
// promoted probes localMemo. A different instance with the same inputs keeps
// the pending value for the instances after it. On a miss it returns the
// pending entry to record for these inputs, with the digest if one was taken.
func (e *Evaluator) reuseLocal(expr hclsyntax.Expression, inputs map[string]cty.Value) (cty.Value, bool, pendingLocal) {
	next := pendingLocal{addr: e.evalAddr, inputs: inputs}
	p, pending := e.localPending[expr]
	if pending && p.addr == e.evalAddr && sameInputs(p.inputs, inputs) {
		return p.value, true, next
	}
	if _, promoted := e.localPromoted[expr]; promoted {
		next.key, next.keyed = e.keyMemo.inputsKey(inputs), true
		if v, hit := e.localMemo[localMemoKey{expr: expr, inputs: next.key}]; hit {
			return v, true, next
		}
	}
	if !pending || p.addr == e.evalAddr {
		return cty.NilVal, false, next
	}
	if !next.keyed {
		next.key, next.keyed = e.keyMemo.inputsKey(inputs), true
	}
	if !p.keyed {
		p.key, p.keyed = e.keyMemo.inputsKey(p.inputs), true
		e.localPending[expr] = p
	}
	if p.key != next.key {
		return cty.NilVal, false, next
	}
	if e.promoteLocal(expr, next.key, p.value) {
		delete(e.localPending, expr)
	}
	return p.value, true, next
}

// promoteLocal shares a value with the instances after the second one. A full
// localMemo keeps the pending entry instead, which later instances still
// compare against.
func (e *Evaluator) promoteLocal(expr hclsyntax.Expression, key inputsDigest, v cty.Value) bool {
	if len(e.localMemo) >= localMemoCap {
		return false
	}
	if e.localMemo == nil {
		e.localMemo = make(map[localMemoKey]cty.Value)
		e.localPromoted = make(map[hclsyntax.Expression]struct{})
	}
	e.localMemo[localMemoKey{expr: expr, inputs: key}] = v
	e.localPromoted[expr] = struct{}{}
	return true
}

// sameInputs reports whether two local-input maps are the values one instance
// already evaluated. A collection is the same only when it shares storage, so
// a module that runs once neither hashes nor walks it.
func sameInputs(a, b map[string]cty.Value) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok {
			return false
		}
		if isCollectionOrStructural(av.Type()) || isCollectionOrStructural(bv.Type()) {
			if !sharesStorage(av, bv) {
				return false
			}
			continue
		}
		if !av.RawEquals(bv) {
			return false
		}
	}
	return true
}

func (e *Evaluator) rememberLocal(expr hclsyntax.Expression, p *pendingLocal) {
	if e.localPending == nil {
		e.localPending = make(map[hclsyntax.Expression]pendingLocal)
	}
	e.localPending[expr] = *p
}

func evalLocal(expr hclsyntax.Expression, ctx *hcl.EvalContext) cty.Value {
	v, diags := expr.Value(ctx)
	if diags.HasErrors() {
		v = partial.WithUnknownRefs(expr, ctx)
	}
	return v
}

func (e *Evaluator) localReadsOf(expr hclsyntax.Expression) localReads {
	if reads, ok := e.localReads[expr]; ok {
		return reads
	}
	reads := localReads{shareable: true}
	for _, t := range expr.Variables() {
		switch t.RootName() {
		case rootVar, rootLocal:
			reads.refs = append(reads.refs, t)
		case rootPath, rootTerraform:
		default:
			reads = localReads{}
		}
		if !reads.shareable {
			break
		}
	}
	if e.localReads == nil {
		e.localReads = make(map[hclsyntax.Expression]localReads)
	}
	e.localReads[expr] = reads
	return reads
}

// localInputs returns the values refs read, each taken at the deepest static
// step of its traversal, so a local reading one attribute of a configuration
// is keyed by that attribute rather than the whole configuration.
func localInputs(refs []hcl.Traversal, ctx *hcl.EvalContext) (map[string]cty.Value, bool) {
	path, ok := ctyutil.LookupVariable(ctx, rootPath)
	if !ok || path.IsMarked() || !path.IsWhollyKnown() || !path.Type().IsObjectType() {
		return nil, false
	}
	// path.* is rebuilt for every module evaluation, so its attributes are
	// keyed as strings: digesting the object would memoize one per evaluation.
	inputs := make(map[string]cty.Value, len(refs)+len(path.Type().AttributeTypes()))
	for name := range path.Type().AttributeTypes() {
		inputs[rootPath+"\x00"+name] = path.GetAttr(name)
	}
	for _, t := range refs {
		root := t.RootName()
		v, ok := ctyutil.LookupVariable(ctx, root)
		if !ok {
			inputs[root+"\x00!"] = cty.True
			continue
		}
		name := root
		for _, step := range t[1:] {
			next, label, found := traverseStatic(v, step)
			if found == stepAbsent {
				// A step known to be absent fails the same whatever else v holds, so
				// key the read by the absence rather than by v.
				v, name = cty.True, name+"\x00"+label+"\x00!"
				break
			}
			if found != stepFound {
				break
			}
			v, name = next, name+"\x00"+label
		}
		// A memo key records only "?" and the type for an unknown, so a plain
		// unknown and one refined with a prefix or non-null would share a value.
		if v.IsMarked() || !v.IsWhollyKnown() {
			return nil, false
		}
		inputs[name] = v
	}
	return inputs, true
}

type stepResult int

const (
	stepUnresolved stepResult = iota
	stepFound
	// stepAbsent is a step v is known to lack, which fails the same whatever
	// else v holds.
	stepAbsent
)

// traverseStatic applies an attribute or literal index step to v, when v is a
// known value the step resolves in.
func traverseStatic(v cty.Value, step hcl.Traverser) (cty.Value, string, stepResult) {
	key, ok := stepKey(step)
	if !ok || v.IsMarked() || !v.IsKnown() || v.IsNull() {
		return cty.NilVal, "", stepUnresolved
	}
	t := v.Type()
	switch {
	case key.Type() == cty.String && t.IsObjectType():
		name := key.AsString()
		if !t.HasAttribute(name) {
			return cty.NilVal, strconv.Quote(name), stepAbsent
		}
		return v.GetAttr(name), strconv.Quote(name), stepFound
	case key.Type() == cty.String && t.IsMapType(),
		key.Type() == cty.Number && (t.IsListType() || t.IsTupleType()):
		if !v.HasIndex(key).True() {
			return cty.NilVal, stepLabel(key), stepAbsent
		}
		return v.Index(key), stepLabel(key), stepFound
	}
	return cty.NilVal, "", stepUnresolved
}

// stepKey is the key an attribute or literal index step reads.
func stepKey(step hcl.Traverser) (cty.Value, bool) {
	var key cty.Value
	switch s := step.(type) {
	case hcl.TraverseAttr:
		key = cty.StringVal(s.Name)
	case hcl.TraverseIndex:
		key = s.Key
	default:
		return cty.NilVal, false
	}
	return key, !key.IsMarked() && key.IsKnown() && !key.IsNull()
}

func stepLabel(key cty.Value) string {
	if key.Type() == cty.String {
		return strconv.Quote(key.AsString())
	}
	return "[" + key.AsBigFloat().Text('f', -1) + "]"
}
