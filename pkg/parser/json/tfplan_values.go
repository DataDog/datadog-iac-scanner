/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package json

import (
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/partial"
	"github.com/tidwall/gjson"
)

const (
	linesKey       = "_dd_lines"
	lineKey        = "_dd_line"
	arrKey         = "_dd_arr"
	defaultLineKey = "_dd__default"
)

// planValues rewrites the planned values of the resource at addr with its
// after_unknown and configuration expressions.
func (c *resourceChangeCorrelation) planValues(addr string, values map[string]any) (unknown, configured map[string]any) {
	if values == nil {
		return nil, nil
	}
	canonical := canonicalConfigAddress(addr)
	var expressions *gjson.Result
	if c.declared[canonical] {
		e := c.configByAddress[canonical]
		expressions = &e
	}
	unknown, configured = planValues(values, c.afterUnknownByAddress[addr], expressions)
	provisioners := c.provisionersByAddress[canonical]
	if provisioners := renderProvisioners(&provisioners); provisioners != nil {
		values[provisionerKey] = provisioners
	}
	return unknown, configured
}

// planValues rewrites one resource's planned values in place and returns its
// _dd_meta.unknown and _dd_meta.configured, each nil when empty. A nil
// expressions means the plan has no configuration for the resource: nothing
// is known to be written, so unknown is left whole.
func planValues(values map[string]any, afterUnknown any, expressions *gjson.Result) (unknown, configured map[string]any) {
	unknown, _ = pruneUnknown(afterUnknown).(map[string]any)
	declared := expressions != nil
	if !declared {
		expressions = &gjson.Result{}
	}
	shape := rewriteObject(values, unknown, newBlockConfig([]gjson.Result{*expressions}), modeBlock)
	useConfiguredText(values, expressions)
	if declared {
		unknown, _ = restrictUnknown(unknown, shape).(map[string]any)
		if len(shape) > 0 {
			configured = shape
		}
	}
	// rewriteObject deletes the entries a configured constant makes known,
	// which can leave empty objects behind.
	unknown, _ = pruneUnknown(unknown).(map[string]any)
	return unknown, configured
}

// hashedAttributes are attributes a provider may plan as a hash of the
// configured value (aws_instance.user_data is planned as its SHA1). A source
// scan reads the configured text, so a constant configuration replaces the
// planned hash. An interpolated one keeps the hash: the plan has no text for it.
var hashedAttributes = [...]string{"user_data", "user_data_base64"}

func useConfiguredText(values map[string]any, expressions *gjson.Result) {
	for _, k := range hashedAttributes {
		if _, planned := values[k].(string); !planned {
			continue
		}
		if text := expressions.Get(k + ".constant_value"); text.Type == gjson.String {
			values[k] = text.String()
		}
	}
}

const provisionerKey = "provisioner"

// renderProvisioners renders a configuration's provisioners in the source
// document shape: provisioner.<type> is the list of that type's blocks.
func renderProvisioners(provisioners *gjson.Result) map[string]any {
	if !provisioners.IsArray() {
		return nil
	}
	out := map[string]any{}
	for _, p := range provisioners.Array() {
		typ := p.Get("type").String()
		if typ == "" {
			continue
		}
		expressions := p.Get("expressions")
		block, _ := renderBody(&expressions)
		list, _ := out[typ].([]any)
		out[typ] = append(list, block)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// renderBody renders a configuration body, whose values the plan does not
// plan, in the source document shape: constants keep their value, other
// expressions are unknown, nested blocks are lists of bodies. unknown is the
// body's _dd_meta.unknown shape, nil when every value is known.
func renderBody(body *gjson.Result) (out, unknown map[string]any) {
	out, unknown = map[string]any{}, map[string]any{}
	if lines := body.Get(linesKey); lines.IsObject() {
		out[linesKey] = lines.Value()
	}
	body.ForEach(func(key, expr gjson.Result) bool {
		k := key.String()
		if k == linesKey {
			return true
		}
		switch {
		case expr.IsArray():
			blocks, blockUnknowns := renderBlocks(expr.Array())
			out[k] = blocks
			if blockUnknowns != nil {
				unknown[k] = blockUnknowns
			}
		case !isExpression(&expr):
			if expr.IsObject() {
				blocks, blockUnknowns := renderBlocks([]gjson.Result{expr})
				out[k] = blocks
				if blockUnknowns != nil {
					unknown[k] = blockUnknowns
				}
			}
		default:
			constant := expr.Get(constantValueKey)
			switch {
			case expr.Get(referencesKey).Exists() || !constant.Exists():
				out[k] = partial.UnknownPlaceholder
				unknown[k] = true
			case constant.Type != gjson.Null:
				out[k] = constant.Value()
			}
		}
		return true
	})
	if len(unknown) == 0 {
		unknown = nil
	}
	return out, unknown
}

// renderBlocks renders nested block bodies and their unknown shapes, nil when
// every value is known.
func renderBlocks(bodies []gjson.Result) (blocks, unknown []any) {
	blocks, unknown = make([]any, len(bodies)), make([]any, len(bodies))
	found := false
	for i := range bodies {
		block, blockUnknown := renderBody(&bodies[i])
		blocks[i], unknown[i] = block, map[string]any{}
		if blockUnknown != nil {
			unknown[i], found = blockUnknown, true
		}
	}
	if !found {
		unknown = nil
	}
	return blocks, unknown
}

// pruneUnknown reduces an after_unknown value to the _dd_meta.unknown shape, nil when nothing is unknown.
func pruneUnknown(afterUnknown any) any {
	switch au := afterUnknown.(type) {
	case bool:
		if au {
			return true
		}
	case map[string]any:
		out := make(map[string]any)
		for k, v := range au {
			if p := pruneUnknown(v); p != nil {
				out[k] = p
			}
		}
		if len(out) > 0 {
			return out
		}
	case []any:
		out := make([]any, len(au))
		found := false
		for i, v := range au {
			if p := pruneUnknown(v); p != nil {
				out[i], found = p, true
			} else if _, isObject := v.(map[string]any); isObject {
				out[i] = map[string]any{}
			} else {
				out[i] = false
			}
		}
		if found {
			return out
		}
	}
	return nil
}

// restrictUnknown keeps the part of unknown under a path the configured shape
// lists: what is unknown but not written, such as a computed id, is dropped.
func restrictUnknown(unknown, shape any) any {
	switch s := shape.(type) {
	case map[string]any:
		u, ok := unknown.(map[string]any)
		if !ok {
			return unknown
		}
		out := map[string]any{}
		for k, v := range u {
			if keyShape, written := s[k]; written {
				out[k] = restrictUnknown(v, keyShape)
			}
		}
		return out
	case []any:
		u, ok := unknown.([]any)
		if !ok {
			return unknown
		}
		out := make([]any, len(u))
		for i, v := range u {
			out[i] = v
			if i < len(s) {
				out[i] = restrictUnknown(v, s[i])
			}
		}
		return out
	}
	return unknown
}

// blockConfig holds the configuration at one nested block level. Nested block
// instances are not in planned-set order, so every planned instance is matched
// against the union. single marks the blocks written as one object rather than
// a list (timeouts, single nested blocks).
type blockConfig struct {
	instances []gjson.Result
	nested    map[string][]gjson.Result
	attrs     map[string]gjson.Result
	single    map[string]bool
}

func newBlockConfig(instances []gjson.Result) blockConfig {
	cfg := blockConfig{
		instances: instances,
		nested:    make(map[string][]gjson.Result),
		attrs:     make(map[string]gjson.Result),
		single:    make(map[string]bool),
	}
	for i := range instances {
		instances[i].ForEach(func(key, expr gjson.Result) bool {
			k := key.String()
			if k == linesKey {
				return true
			}
			switch {
			case expr.IsArray():
				cfg.nested[k] = append(cfg.nested[k], expr.Array()...)
			case expr.IsObject() && !isExpression(&expr):
				cfg.nested[k] = append(cfg.nested[k], expr)
				cfg.single[k] = true
			case isConstantNull(&expr):
				// Terraform treats null as unset: the attribute is not configured.
			default:
				if _, seen := cfg.attrs[k]; !seen {
					cfg.attrs[k] = expr
				}
				if _, seen := cfg.nested[k]; !seen {
					cfg.nested[k] = nil
				}
			}
			return true
		})
	}
	return cfg
}

func (c blockConfig) lookup(k string) (instances []gjson.Result, configured bool) {
	if c.nested != nil {
		if inst, ok := c.nested[k]; ok {
			return inst, true
		}
	}
	if c.attrs != nil {
		if _, ok := c.attrs[k]; ok {
			return nil, true
		}
	}
	return nil, false
}

// configuredConstant is the known constant_value of attr, if every
// configuration instance at this level sets the same one. A planned set does
// not keep the configuration's order, so a planned instance cannot be matched
// to one configuration instance. Empty string is a constant; null is not
// configured.
func (c blockConfig) configuredConstant(k string) (any, bool) {
	if len(c.instances) == 0 {
		return nil, false
	}
	// Raw JSON equality: representation-sensitive (1 vs 1.0 disagree). Fail
	// closed so a constant is restored only when every instance agrees.
	var raw string
	var value any
	for i := range c.instances {
		expr := c.instances[i].Get(gjsonKey(k))
		constant, ok := constantOf(&expr)
		if !ok || i > 0 && constant.Raw != raw {
			return nil, false
		}
		raw = constant.Raw
		value = constant.Value()
	}
	return value, true
}

// constantOf is the constant_value of an expression that reads nothing.
func constantOf(expr *gjson.Result) (gjson.Result, bool) {
	if !isExpression(expr) || expr.Get(referencesKey).Exists() {
		return gjson.Result{}, false
	}
	constant := expr.Get(constantValueKey)
	if !constant.Exists() || constant.Type == gjson.Null {
		return gjson.Result{}, false
	}
	return constant, true
}

// valueMode is how rewriteObject reads one level of planned values.
type valueMode int

const (
	// modeBlock reads a block level against its configuration; a level the
	// configuration does not show has nothing written.
	modeBlock valueMode = iota
	// modeDynamic reads a block the configuration leaves out but that may be
	// written, such as a dynamic block: every key counts as written.
	modeDynamic
	// modeAttribute reads a written attribute's value, kept as planned.
	modeAttribute
)

// rewriteObject rewrites one object level. Unknown values nobody configured
// stay absent, and outside an attribute's value an empty list nobody
// configured is dropped: an absent list and an empty one are the same.
//
// It returns the configured shape of a block level: true at each attribute
// the configuration sets, a list of shapes at each nested block.
func rewriteObject(obj, unknown map[string]any, cfg blockConfig, mode valueMode) map[string]any {
	if mode == modeBlock {
		wrapSingleBlocks(obj, unknown, cfg)
	}
	fillUnknown(obj, unknown, cfg, mode)
	shape := map[string]any{}
	for k, v := range obj {
		if k == linesKey {
			continue
		}
		nested, nestedMode, written, keep := cfg.keyConfig(k, v, mode)
		if !keep || v == nil {
			delete(obj, k)
			continue
		}
		var nestedShape any
		switch v.(type) {
		case []any, map[string]any:
			nestedShape = rewriteValue(v, unknown[k], nested, nestedMode)
		}
		if !written || (mode != modeBlock && mode != modeDynamic) {
			continue
		}
		if (nestedMode == modeBlock || nestedMode == modeDynamic) && nestedShape != nil {
			shape[k] = nestedShape
		} else {
			shape[k] = true
		}
	}
	return shape
}

// keyConfig is how rewriteObject reads key k of a level holding v: the
// configuration of its nested blocks and how to read them, whether k is
// written, and false when v is an empty list nobody configured.
func (cfg blockConfig) keyConfig(k string, v any, mode valueMode) (nested blockConfig, nestedMode valueMode, written, keep bool) {
	switch mode {
	case modeAttribute:
		return blockConfig{}, modeAttribute, false, true
	case modeDynamic:
		// Everything in a dynamic instance is written; nested objects recurse
		// as dynamic so their attributes become configured shapes.
		if isEmptyList(v) {
			return blockConfig{}, modeDynamic, false, false
		}
		switch v.(type) {
		case map[string]any:
			return blockConfig{}, modeDynamic, true, true
		case []any:
			if isDynamicBlock(v) {
				return blockConfig{}, modeDynamic, true, true
			}
			return blockConfig{}, modeAttribute, true, true
		}
		return blockConfig{}, modeDynamic, true, true
	}
	instances, configured := cfg.lookup(k)
	switch {
	case configured && len(instances) > 0:
		return newBlockConfig(instances), modeBlock, true, true
	case configured:
		return blockConfig{}, modeAttribute, true, true
	case isEmptyList(v):
		return blockConfig{}, modeBlock, false, false
	case isDynamicBlock(v):
		return blockConfig{}, modeDynamic, true, true
	}
	return blockConfig{}, modeBlock, false, true
}

func isEmptyList(v any) bool {
	l, ok := v.([]any)
	return ok && len(l) == 0
}

// isDynamicBlock reports whether an unconfigured key's planned value is a
// list of blocks. Configuration expressions leave dynamic blocks out, so such
// a list is treated as written. The plan cannot tell it from a computed list
// of objects the provider fills, which is treated as written too. A map is
// never a block.
func isDynamicBlock(v any) bool {
	l, ok := v.([]any)
	if !ok || len(l) == 0 {
		return false
	}
	_, block := l[0].(map[string]any)
	return block
}

// wrapSingleBlocks turns each block the configuration writes as one object
// into a one-element list, the shape of every nested block.
func wrapSingleBlocks(obj, unknown map[string]any, cfg blockConfig) {
	for k := range cfg.single {
		if v, ok := obj[k].(map[string]any); ok {
			obj[k] = []any{v}
			wrapLineEntry(obj, k)
		}
		if u, ok := unknown[k].(map[string]any); ok {
			unknown[k] = []any{u}
		}
	}
}

// wrapLineEntry gives the line entry of key k, now a one-element list, the
// element's line.
func wrapLineEntry(obj map[string]any, k string) {
	lines, _ := obj[linesKey].(map[string]any)
	entry, _ := lines["_dd_"+k].(map[string]any)
	if entry == nil {
		return
	}
	entry[arrKey] = []any{map[string]any{defaultLineKey: map[string]any{lineKey: entry[lineKey]}}}
}

func fillUnknown(obj, unknown map[string]any, cfg blockConfig, mode valueMode) {
	for k, u := range unknown {
		if mode == modeBlock {
			if _, configured := cfg.lookup(k); !configured {
				continue
			}
		}
		switch u := u.(type) {
		case bool:
			if !u {
				continue
			}
			// A configured constant is known even when after_unknown says true
			// (providers mark empty strings unknown on refresh/update plans).
			if constant, ok := cfg.configuredConstant(k); ok {
				obj[k] = constant
				delete(unknown, k)
				continue
			}
			// A static nested block next to an unknown dynamic block of the
			// same type is marked unknown as a whole. Keep the written
			// instances in the body and leave the type-level unknown marker.
			if instances, configured := cfg.lookup(k); configured && len(instances) > 0 {
				blocks, _ := renderBlocks(instances)
				obj[k] = blocks
				continue
			}
			obj[k] = partial.UnknownPlaceholder
		case map[string]any:
			if _, ok := obj[k].(map[string]any); !ok {
				obj[k] = map[string]any{}
			}
		case []any:
			if _, ok := obj[k].([]any); !ok {
				obj[k] = unknownList(u)
			}
		}
	}
}

// unknownList builds the structure of a list missing from planned values;
// rewriteValue then fills its unknown positions and its known ones stay null.
func unknownList(unknown []any) []any {
	out := make([]any, len(unknown))
	for i, u := range unknown {
		switch elem := u.(type) {
		case map[string]any:
			out[i] = map[string]any{}
		case []any:
			out[i] = unknownList(elem)
		}
	}
	return out
}

// isExpression reports whether expr is one attribute's configuration:
// constant_value, references, or neither for an expression the plan has no
// constant or reference for (timestamp()). Line info is stored on the same
// object and is not part of the expression. A body is never an expression,
// even an empty one: only the caller knows which it reads.
func isExpression(expr *gjson.Result) bool {
	if !expr.IsObject() {
		return false
	}
	attribute := true
	expr.ForEach(func(key, _ gjson.Result) bool {
		if key.String() == linesKey {
			return true
		}
		attribute = key.String() == constantValueKey || key.String() == referencesKey
		return attribute
	})
	return attribute
}

// rewriteValue rewrites a nested value and returns its configured shape: an
// object's shape, or for a list the shape of each element ({} when an element
// sets nothing).
func rewriteValue(value, unknown any, cfg blockConfig, mode valueMode) any {
	switch val := value.(type) {
	case map[string]any:
		u, _ := unknown.(map[string]any)
		return rewriteObject(val, u, cfg, mode)
	case []any:
		u, _ := unknown.([]any)
		shapes := make([]any, len(val))
		for i, elem := range val {
			shapes[i] = map[string]any{}
			var elemUnknown any
			if i < len(u) {
				elemUnknown = u[i]
			}
			if elemUnknown == true {
				if mode != modeBlock {
					val[i] = partial.UnknownPlaceholder
				}
				continue
			}
			if s := rewriteValue(elem, elemUnknown, cfg, mode); s != nil {
				shapes[i] = s
			}
		}
		return shapes
	}
	return nil
}

// isConstantNull reports whether expr is the expression of an attribute set
// to null.
func isConstantNull(expr *gjson.Result) bool {
	if !isExpression(expr) || expr.Get(referencesKey).Exists() {
		return false
	}
	constant := expr.Get(constantValueKey)
	return constant.Exists() && constant.Type == gjson.Null
}
