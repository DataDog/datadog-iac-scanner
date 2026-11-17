/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// planSections are the top-level members of a plan whose source ranges
// locate blocks.
var planSections = map[string]bool{"planned_values": true, "prior_state": true, "configuration": true}

// loadPlan models a Terraform plan JSON file as its own root. Attributes are
// the planned values at the paths the configuration writes; the other planned
// values are computed. References come from the configuration expressions.
func loadPlan(ctx context.Context, fsys vfs.FS, base, path string) *Root {
	root := &Root{ID: rootID(base, path), Dir: filepath.Dir(path), Plan: true}
	fail := func(note string, err error) *Root {
		root.Incomplete, root.Unscoped, root.Degraded = true, true, true
		root.Notes = append(root.Notes, note)
		contextLogger := logger.FromContext(ctx)
		contextLogger.Info().Err(err).Str("file", path).Msg("terraform model: " + note)
		return root
	}
	src, err := fsys.ReadFile(path)
	if err != nil {
		return fail("plan could not be read", err)
	}
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return fail("plan is not valid JSON", err)
	}
	pos, err := jsonPositions(path, src, planSections)
	if err != nil {
		return fail("plan is not valid JSON", err)
	}
	b := &planBuilder{
		root: root, path: path, file: relPath(base, path), doc: doc, pos: pos,
		modules: map[string]*Module{}, config: map[*Module]map[string]any{},
		unknown: map[string]any{}, deleted: map[string]bool{},
		providerKeys: map[*Block]string{}, modulePos: map[string]*jsonNode{},
	}
	b.build()
	for _, note := range root.Notes {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Info().Str("file", path).Msg("terraform model: " + note)
	}
	return root
}

type planBuilder struct {
	root *Root
	// path is the plan's absolute path, file its path relative to the base.
	path string
	file string
	doc  map[string]any
	pos  *jsonNode
	// modules holds the module instances by address.
	modules map[string]*Module
	// config holds the configuration module of each module instance, nil
	// when the plan has none for it.
	config map[*Module]map[string]any
	// unknown holds after_unknown by instance address.
	unknown map[string]any
	deleted map[string]bool
	// blocks holds, per module instance, its blocks by address.
	blocks       map[*Module]map[string][]*Block
	providers    map[string]*Block
	providerKeys map[*Block]string
	// modulePos holds the planned values entry of each module instance.
	modulePos map[string]*jsonNode
	// bare is a configuration that lists resources without any expressions:
	// it does not say what is written, so every planned value counts as
	// written.
	bare bool
	// configByAddr indexes each module's configuration resources by address
	// and list index, so instance fills do not rescan the resources list.
	configByAddr map[*Module]map[string]configResourceRef
}

// configResourceRef is one entry of configuration.resources.
type configResourceRef struct {
	cfg map[string]any
	i   int
}

func (b *planBuilder) incomplete(note string) {
	b.root.Incomplete, b.root.Unscoped = true, true
	b.root.Notes = append(b.root.Notes, note)
}

func (b *planBuilder) build() {
	if errored, _ := b.doc["errored"].(bool); errored {
		b.incomplete("plan errored")
	}
	if complete, ok := b.doc["complete"].(bool); ok && !complete {
		b.incomplete("plan is not complete")
	}
	if deferred, _ := b.doc["deferred_changes"].([]any); len(deferred) > 0 {
		b.incomplete("plan defers changes")
	}
	if _, ok := object(b.doc, "configuration", "root_module"); !ok {
		b.incomplete("plan has no configuration")
	}
	for _, rc := range list(b.doc, "resource_changes") {
		change, _ := rc.(map[string]any)
		addr, _ := change["address"].(string)
		inner, _ := change["change"].(map[string]any)
		if addr == "" || inner == nil {
			continue
		}
		if u, ok := inner["after_unknown"]; ok {
			b.unknown[addr] = u
		}
		if actions, _ := inner["actions"].([]any); len(actions) == 1 && actions[0] == "delete" {
			b.deleted[addr] = true
		}
	}

	b.bare = bareConfig(b.doc)
	b.module("")
	b.blocks = map[*Module]map[string][]*Block{}
	if rm, ok := object(b.doc, "planned_values", "root_module"); ok {
		b.walkModule(rm, b.pos.kid("planned_values", "root_module"), false)
	} else {
		b.incomplete("plan has no planned values")
	}
	if rm, ok := object(b.doc, "prior_state", "values", "root_module"); ok {
		b.walkModule(rm, b.pos.kid("prior_state", "values", "root_module"), true)
	}
	// Module calls that plan no resources still exist in configuration: create
	// their instances so variables, outputs and the calls themselves project.
	b.ensureConfigModules(b.modules[""])
	b.configOnlyBlocks()
	sort.SliceStable(b.root.Modules[1:], func(i, j int) bool {
		return b.root.Modules[i+1].Address < b.root.Modules[j+1].Address
	})
	seen := map[string]bool{}
	for _, m := range b.root.Modules {
		path := configPath(m.Address)
		m.Static = !seen[path]
		seen[path] = true
	}
	b.providerBlocks()
	b.variableBlocks()
	b.outputBlocks()
	b.moduleCallBlocks()
	markDuplicates(b.root)
	b.trace()
	b.root.Notes = slices.Compact(b.root.Notes)
}

// ensureConfigModules creates a module instance for every configuration
// module_call that planned no child module, then walks nested calls.
func (b *planBuilder) ensureConfigModules(parent *Module) {
	if parent == nil {
		return
	}
	calls, _ := object(b.config[parent], "module_calls")
	for _, label := range sortedMapKeys(calls) {
		call, _ := calls[label].(map[string]any)
		if zeroConfigInstances(call) {
			continue
		}
		children := parent.calls[label]
		if len(children) == 0 {
			children = []*Module{b.module(joinAddr(parent.Address, address.KindModule+"."+label))}
		}
		for _, child := range children {
			b.ensureConfigModules(child)
		}
	}
}

// bareConfig reports a plan whose configuration declares resources and no
// expression for any of them.
func bareConfig(doc map[string]any) bool {
	mod, ok := object(doc, "configuration", "root_module")
	if !ok {
		return false
	}
	resources := 0
	var walk func(map[string]any) bool
	walk = func(m map[string]any) bool {
		for _, r := range list(m, "resources") {
			res, _ := r.(map[string]any)
			if _, ok := res["expressions"]; ok {
				return false
			}
			resources++
		}
		calls, _ := m["module_calls"].(map[string]any)
		for _, c := range calls {
			call, _ := c.(map[string]any)
			if child, ok := object(call, "module"); ok && !walk(child) {
				return false
			}
		}
		return true
	}
	return walk(mod) && resources > 0
}

// configOnlyBlocks models, from their configuration expressions, the data
// sources a module's configuration declares without count or for_each and
// that neither the planned values nor the prior state hold, such as a data
// source an errored plan never read. A managed resource the plan does not
// hold is not created.
func (b *planBuilder) configOnlyBlocks() {
	for _, m := range slices.Clone(b.root.Modules) {
		for i, r := range list(b.config[m], "resources") {
			cfg, _ := r.(map[string]any)
			kind, typ, name, _, ok := plannedResource(cfg)
			if !ok || kind != address.KindData || cfg["count_expression"] != nil || cfg["for_each_expression"] != nil {
				continue
			}
			ab := address.Block{Kind: kind, Type: typ, Name: name}
			baddr := address.Addr(ab)
			if len(b.blocks[m][baddr]) > 0 {
				continue
			}
			pos := b.configPos(m, "resources", strconv.Itoa(i))
			blk := b.blockFor(m, ab, joinAddr(m.Address, baddr), pos, false)
			b.configure(blk, m, baddr, typ, cfg)
			expressions, _ := cfg["expressions"].(map[string]any)
			inst := &Instance{
				Block: blk, Address: joinAddr(m.Address, baddr),
				Attrs: planValues(configuredValues(expressions)), Ranges: map[string]hcl.Range{"": blk.Range},
			}
			pos.kid("expressions").flatten("", inst.Ranges)
			blk.Instances = append(blk.Instances, inst)
		}
	}
}

// zeroConfigInstances reports a module call whose count or for_each is a
// known empty expansion, so the configuration creates no instance.
func zeroConfigInstances(call map[string]any) bool {
	if count, ok := call["count_expression"].(map[string]any); ok {
		if n, ok := count["constant_value"].(json.Number); ok {
			i, err := n.Int64()
			return err == nil && i == 0
		}
		if f, ok := count["constant_value"].(float64); ok {
			return f == 0
		}
	}
	each, ok := call["for_each_expression"].(map[string]any)
	if !ok {
		return false
	}
	switch v := each["constant_value"].(type) {
	case []any:
		return len(v) == 0
	case map[string]any:
		return len(v) == 0
	}
	return false
}

// module returns the module instance at addr, creating it and its parents.
func (b *planBuilder) module(addr string) *Module {
	if m, ok := b.modules[addr]; ok {
		return m
	}
	m := &Module{Root: b.root, Address: addr, Dir: b.root.Dir}
	b.modules[addr] = m
	if addr != "" {
		m.parent = b.module(parentModule(addr))
		label := callLabel(addr)
		if m.parent.calls == nil {
			m.parent.calls = map[string][]*Module{}
		}
		m.parent.calls[label] = append(m.parent.calls[label], m)
	}
	b.config[m] = b.configModule(addr)
	b.root.Modules = append(b.root.Modules, m)
	return m
}

// configModule returns the configuration of the module at addr (instance
// keys ignored), nil when the plan has none.
func (b *planBuilder) configModule(addr string) map[string]any {
	cfg, ok := object(b.doc, "configuration", "root_module")
	if !ok {
		return nil
	}
	for _, name := range moduleNames(addr) {
		cfg, ok = object(cfg, "module_calls", name, "module")
		if !ok {
			return nil
		}
	}
	return cfg
}

// configCall returns the configuration of the call to module instance m.
func (b *planBuilder) configCall(m *Module) map[string]any {
	if m.parent == nil {
		return nil
	}
	call, _ := object(b.config[m.parent], "module_calls", callLabel(m.Address))
	return call
}

func (b *planBuilder) walkModule(mod map[string]any, pos *jsonNode, prior bool) {
	addr, _ := mod["address"].(string)
	addr = normalizeModuleAddr(addr)
	if _, ok := b.modulePos[addr]; !ok && addr != "" {
		b.modulePos[addr] = pos
	}
	for i, r := range list(mod, "resources") {
		res, ok := r.(map[string]any)
		if !ok {
			continue
		}
		b.resource(addr, res, pos.kid("resources", strconv.Itoa(i)), prior)
	}
	for i, c := range list(mod, "child_modules") {
		if child, ok := c.(map[string]any); ok {
			b.walkModule(child, pos.kid("child_modules", strconv.Itoa(i)), prior)
		}
	}
}

// plannedResource reads a planned resource entry. ok is false for a mode the
// model does not project or an entry without a type and name.
func plannedResource(res map[string]any) (kind, typ, name, full string, ok bool) {
	mode, _ := res["mode"].(string)
	typ, _ = res["type"].(string)
	name, _ = res["name"].(string)
	full, _ = res["address"].(string)
	switch mode {
	case "managed":
		kind = address.KindResource
	case address.KindData:
		kind = address.KindData
	default:
		return "", "", "", "", false
	}
	if typ == "" || name == "" {
		return "", "", "", "", false
	}
	return kind, typ, name, full, true
}

func (b *planBuilder) resource(modAddr string, res map[string]any, pos *jsonNode, prior bool) {
	kind, typ, name, full, ok := plannedResource(res)
	if !ok || (prior && (kind != address.KindData || b.deleted[full])) {
		return
	}
	m := b.module(modAddr)
	key := ""
	if idx, ok := res["index"]; ok && idx != nil {
		key = address.InstanceSuffix(planValue(idx))
	}
	ab := address.Block{Kind: kind, Type: typ, Name: name}
	inst := &Instance{Key: key, Address: joinAddr(m.Address, address.Addr(ab)+key)}
	baddr := address.Addr(ab)
	blk := b.blockFor(m, ab, inst.Address, pos, prior)
	if blk == nil {
		return
	}
	cfg := b.configResource(m, baddr)
	if len(blk.Instances) == 0 {
		b.configure(blk, m, baddr, typ, cfg)
	}
	b.fill(blk, inst, res, full, pos, cfg)
	b.addConfigRanges(inst, m, baddr)
}

// blockFor returns the block instAddr belongs to, creating it. A prior-state
// entry of a block the plan already holds, and a repeated instance address,
// give nil: prior state only adds what the plan omitted, and a repeated
// address is a second block.
func (b *planBuilder) blockFor(m *Module, ab address.Block, instAddr string, pos *jsonNode, prior bool) *Block {
	blocks := b.blocks[m]
	if blocks == nil {
		blocks = map[string][]*Block{}
		b.blocks[m] = blocks
	}
	baddr := address.Addr(ab)
	if list := blocks[baddr]; len(list) > 0 {
		if prior {
			return nil
		}
		blk := list[len(list)-1]
		if !slices.ContainsFunc(blk.Instances, func(o *Instance) bool { return o.Address == instAddr }) {
			return blk
		}
	}
	blk := &Block{Module: m, Kind: ab.Kind, Type: ab.Type, Name: ab.Name, File: b.file, Range: b.rangeOf(pos)}
	blocks[baddr] = append(blocks[baddr], blk)
	m.Blocks = append(m.Blocks, blk)
	return blk
}

// configure records what the configuration says about a new block.
func (b *planBuilder) configure(blk *Block, m *Module, baddr, typ string, cfg map[string]any) {
	if cfg == nil {
		if _, ok := object(b.doc, "configuration", "root_module"); ok {
			b.incomplete("no configuration for " + joinAddr(configPath(m.Address), baddr))
		}
		return
	}
	var providerKey string
	blk.Provider, providerKey = resourceProvider(cfg, typ)
	b.providerKeys[blk] = providerKey
	blk.DependsOn = stringList(cfg["depends_on"])
}

// fill sets the instance's values from the planned values and the
// configuration, and appends it to its block.
func (b *planBuilder) fill(blk *Block, inst *Instance, res map[string]any, full string, pos *jsonNode, cfg map[string]any) {
	inst.Block = blk
	inst.Iteration = planIteration(res["index"])
	values, _ := res["values"].(map[string]any)
	merged, _ := withUnknown(values, b.unknown[full]).(map[string]any)
	var level *configLevel
	if cfg != nil && !b.bare {
		expressions, _ := cfg["expressions"].(map[string]any)
		level = &configLevel{bodies: []map[string]any{expressions}}
	}
	split := &planSplit{}
	attrs, computed := split.object(merged, level, "")
	// Provisioners live only in configuration (never in planned_values); fold
	// them into attrs in the same labeled shape HCL evaluation produces.
	if prov := planProvisioners(cfg); prov != nil {
		attrs["provisioner"] = prov
	}
	inst.Attrs, inst.Computed = planValues(attrs), planValues(computed)
	// An empty finding path is the block header. On a plan that is the
	// values object when present, not the resource wrapper around it.
	inst.Ranges = map[string]hcl.Range{"": b.rangeOf(pos)}
	if valuesPos := pos.kid("values"); valuesPos != nil {
		inst.Ranges[""] = valuesPos.rng
		valuesPos.flatten("", inst.Ranges)
		if len(blk.Instances) == 0 {
			blk.Range = valuesPos.rng
		}
	}
	for _, p := range split.dynamic {
		if inst.Untraced == nil {
			inst.Untraced = map[string]bool{}
		}
		inst.Untraced[namesOnly(p)] = true
	}
	blk.Instances = append(blk.Instances, inst)
}

// planProvisioners builds the provisioner nested block list from a plan
// configuration resource. Terraform omits provisioners from planned_values;
// the configuration lists them as {type, expressions}. The result matches the
// HCL shape: one tuple element whose attributes are the provisioner types
// (a single block of a type is an object, several are a tuple).
func planProvisioners(cfg map[string]any) any {
	raw := list(cfg, "provisioners")
	if len(raw) == 0 {
		return nil
	}
	byType := map[string][]any{}
	for _, p := range raw {
		m, ok := p.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := m["type"].(string)
		if typ == "" {
			continue
		}
		expressions, _ := m["expressions"].(map[string]any)
		byType[typ] = append(byType[typ], configuredValues(expressions))
	}
	if len(byType) == 0 {
		return nil
	}
	obj := make(map[string]any, len(byType))
	for typ, elems := range byType {
		if len(elems) == 1 {
			obj[typ] = elems[0]
		} else {
			obj[typ] = elems
		}
	}
	return []any{obj}
}

// configResource returns the configuration of the block at addr in the
// module of m.
func (b *planBuilder) configResource(m *Module, addr string) map[string]any {
	if ref, ok := b.configResources(m)[addr]; ok {
		return ref.cfg
	}
	return nil
}

// configResources indexes configuration.resources of m by address once.
func (b *planBuilder) configResources(m *Module) map[string]configResourceRef {
	if b.configByAddr == nil {
		b.configByAddr = map[*Module]map[string]configResourceRef{}
	}
	if indexed, ok := b.configByAddr[m]; ok {
		return indexed
	}
	resources := list(b.config[m], "resources")
	indexed := make(map[string]configResourceRef, len(resources))
	for i, r := range resources {
		res, _ := r.(map[string]any)
		addr, _ := res["address"].(string)
		if addr == "" {
			continue
		}
		indexed[addr] = configResourceRef{cfg: res, i: i}
	}
	b.configByAddr[m] = indexed
	return indexed
}

// resourceProvider returns the provider configuration a resource names, as
// written in its module, and its key in configuration.provider_config.
func resourceProvider(cfg map[string]any, typ string) (written, key string) {
	key, _ = cfg["provider_config_key"].(string)
	written = key
	if i := strings.LastIndexByte(written, ':'); i >= 0 {
		written = written[i+1:]
	}
	if written == "" {
		written, _, _ = strings.Cut(typ, "_")
	}
	return written, key
}

// providerBlocks models configuration.provider_config (constants are known,
// every other expression is unknown) and resolves the provider of every
// block from its provider_config_key.
func (b *planBuilder) providerBlocks() {
	b.providers = map[string]*Block{}
	defer func() {
		for blk, key := range b.providerKeys {
			blk.ProviderBlock = b.providers[key]
		}
	}()
	configs, _ := object(b.doc, "configuration", "provider_config")
	for _, key := range sortedMapKeys(configs) {
		pc, _ := configs[key].(map[string]any)
		name, _ := pc["name"].(string)
		if name == "" {
			continue
		}
		alias, _ := pc["alias"].(string)
		modAddr, _ := pc["module_address"].(string)
		m := b.firstInstance(modAddr)
		if m == nil {
			continue
		}
		pos := b.pos.kid("configuration", "provider_config", key)
		blk := &Block{Module: m, Kind: address.KindProvider, Type: name, Name: alias, File: b.file, Range: b.rangeOf(pos)}
		addr := address.Addr(address.Block{Kind: address.KindProvider, Type: name, Name: alias})
		inst := &Instance{Block: blk, Address: joinAddr(m.Address, addr)}
		expressions, _ := pc["expressions"].(map[string]any)
		inst.Attrs = planValues(configuredValues(expressions))
		inst.Ranges = map[string]hcl.Range{"": blk.Range}
		pos.kid("expressions").flatten("", inst.Ranges)
		blk.Instances = []*Instance{inst}
		m.Blocks = append(m.Blocks, blk)
		b.providers[key] = blk
	}
}

// firstInstance returns the first module instance of the module whose
// configuration path is path, nil when it has none.
func (b *planBuilder) firstInstance(path string) *Module {
	if path == "" {
		return b.modules[""]
	}
	var out *Module
	for addr, m := range b.modules {
		if configPath(addr) == path && (out == nil || addr < out.Address) {
			out = m
		}
	}
	return out
}

// configuredValues renders a configuration body: constants keep their
// value, other expressions are unknown, nested blocks are lists of bodies.
func configuredValues(body map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range body {
		switch e := v.(type) {
		case []any:
			blocks := make([]any, 0, len(e))
			for _, nb := range e {
				if m, ok := nb.(map[string]any); ok {
					blocks = append(blocks, configuredValues(m))
				}
			}
			out[k] = blocks
		case map[string]any:
			if !isExpression(e) {
				out[k] = []any{configuredValues(e)}
				continue
			}
			cv, has := e["constant_value"]
			_, refs := e["references"]
			switch {
			case refs || !has:
				out[k] = planUnknown{}
			case cv != nil:
				out[k] = cv
			}
		}
	}
	return out
}

// variableBlocks models configuration variables of every static module.
func (b *planBuilder) variableBlocks() {
	for _, m := range b.root.Modules {
		if !m.Static {
			continue
		}
		variables, _ := object(b.config[m], "variables")
		for _, name := range sortedMapKeys(variables) {
			cfg, _ := variables[name].(map[string]any)
			pos := b.configPos(m, "variables", name)
			blk := &Block{Module: m, Kind: address.KindVariable, Name: name, File: b.file, Range: b.rangeOf(pos)}
			inst := &Instance{
				Block: blk, Address: joinAddr(m.Address, "var."+name),
				Ranges: map[string]hcl.Range{"": blk.Range},
			}
			attrs := map[string]any{}
			for _, k := range []string{"default", "description", "sensitive", "nullable"} {
				if v, ok := cfg[k]; ok && v != nil {
					attrs[k] = v
					if p := pos.kid(k); p != nil {
						inst.Ranges[k] = p.rng
					}
				}
			}
			if t, ok := cfg["type"].(string); ok {
				attrs["type"] = t
				if p := pos.kid("type"); p != nil {
					inst.Ranges["type"] = p.rng
				}
			}
			inst.Attrs = planValues(attrs)
			blk.Instances = []*Instance{inst}
			m.Blocks = append(m.Blocks, blk)
		}
	}
}

// outputBlocks models the outputs of every static module. Root outputs take
// their value from planned_values; nested ones from the configuration
// expression.
func (b *planBuilder) outputBlocks() {
	rootPlanned, _ := object(b.doc, "planned_values", "outputs")
	rootChanges, _ := b.doc["output_changes"].(map[string]any)
	for _, m := range b.root.Modules {
		if !m.Static {
			continue
		}
		outputs, _ := object(b.config[m], "outputs")
		for _, name := range sortedMapKeys(outputs) {
			cfg, _ := outputs[name].(map[string]any)
			b.outputBlock(m, name, cfg, rootPlanned, rootChanges)
		}
	}
}

func (b *planBuilder) outputBlock(m *Module, name string, cfg, rootPlanned, rootChanges map[string]any) {
	pos := b.configPos(m, "outputs", name)
	if m.Address == "" {
		if p := b.pos.kid("planned_values", "outputs", name); p != nil {
			pos = p
		}
	}
	blk := &Block{Module: m, Kind: address.KindOutput, Name: name, File: b.file, Range: b.rangeOf(pos)}
	inst := &Instance{
		Block: blk, Address: joinAddr(m.Address, "output."+name),
		Ranges: map[string]hcl.Range{"": blk.Range},
	}
	attrs := map[string]any{}
	if s, ok := cfg["sensitive"].(bool); ok {
		attrs["sensitive"] = s
	}
	if d, ok := cfg["description"].(string); ok {
		attrs["description"] = d
	}
	attrs["value"] = planOutputValue(m.Address == "", name, cfg, rootPlanned, rootChanges)
	if p := pos.kid("value"); p != nil {
		inst.Ranges["value"] = p.rng
	} else if p := pos.kid("expression"); p != nil {
		inst.Ranges["value"] = p.rng
	}
	inst.Attrs = planValues(attrs)
	blk.Instances = []*Instance{inst}
	m.Blocks = append(m.Blocks, blk)
}

// planOutputValue is a root output's planned value when present, otherwise
// the configuration expression.
func planOutputValue(root bool, name string, cfg, planned, changes map[string]any) any {
	if !root {
		return configExpressionValue(cfg["expression"])
	}
	var value any
	if out, ok := planned[name].(map[string]any); ok {
		value = out["value"]
	}
	if change, ok := changes[name].(map[string]any); ok {
		value = withUnknown(value, change["after_unknown"])
	}
	if value == nil {
		return configExpressionValue(cfg["expression"])
	}
	return value
}

// moduleCallBlocks models the module calls with one instance per module
// instance of the plan, located at the planned values entry when present and
// at the configuration entry otherwise.
func (b *planBuilder) moduleCallBlocks() {
	for _, parent := range slices.Clone(b.root.Modules) {
		for _, label := range sortedMapKeys(parent.calls) {
			children := parent.calls[label]
			sort.Slice(children, func(i, j int) bool { return children[i].Address < children[j].Address })
			call, _ := object(b.config[parent], "module_calls", label)
			attrs := map[string]any{}
			expressions, _ := call["expressions"].(map[string]any)
			for k, v := range configuredValues(expressions) {
				attrs[k] = v
			}
			if s, ok := call["source"].(string); ok {
				attrs["source"] = s
			}
			if v, ok := call["version_constraint"].(string); ok {
				attrs["version"] = v
			}
			callPos := b.configPos(parent, "module_calls", label)
			blk := &Block{Module: parent, Kind: address.KindModule, Name: label, File: b.file}
			blk.Range = b.rangeOf(callPos)
			if p := b.modulePos[children[0].Address]; p != nil {
				blk.Range = b.rangeOf(p)
			}
			prefix := joinAddr(parent.Address, address.KindModule+"."+label)
			for _, child := range children {
				pos := b.modulePos[child.Address]
				if pos == nil {
					pos = callPos
				}
				inst := &Instance{
					Block: blk, Key: strings.TrimPrefix(child.Address, prefix), Address: child.Address,
					Attrs: planValues(attrs), Ranges: map[string]hcl.Range{"": b.rangeOf(pos)},
				}
				if p := callPos.kid("source"); p != nil {
					inst.Ranges["source"] = p.rng
				}
				if p := callPos.kid("version_constraint"); p != nil {
					inst.Ranges["version"] = p.rng
				}
				callPos.kid("expressions").flatten("", inst.Ranges)
				inst.Iteration = iterationOf(inst.Key, cty.NilVal)
				blk.Instances = append(blk.Instances, inst)
			}
			parent.Blocks = append(parent.Blocks, blk)
		}
	}
}

// configPos is the JSON range of a path under the configuration module of m.
func (b *planBuilder) configPos(m *Module, parts ...string) *jsonNode {
	n := b.pos.kid("configuration", "root_module")
	for _, name := range moduleNames(m.Address) {
		n = n.kid("module_calls", name, "module")
	}
	return n.kid(parts...)
}

// configExpressionValue renders a plan configuration expression: a constant
// keeps its value, anything else is unknown, and a missing expression is nil.
func configExpressionValue(v any) any {
	expr, ok := v.(map[string]any)
	if !ok || !isExpression(expr) {
		return nil
	}
	cv, has := expr["constant_value"]
	_, refs := expr["references"]
	switch {
	case refs || !has:
		return planUnknown{}
	case cv != nil:
		return cv
	default:
		return nil
	}
}

// rangeOf is the range of a plan entry, the start of the file when the entry
// was not found.
func (b *planBuilder) rangeOf(n *jsonNode) hcl.Range {
	if n == nil {
		return hcl.Range{Filename: b.path, Start: hcl.InitialPos, End: hcl.InitialPos}
	}
	return n.rng
}

// planIteration binds count.index or each.key for an instance index.
func planIteration(index any) map[string]cty.Value {
	switch x := index.(type) {
	case json.Number:
		return map[string]cty.Value{"count": cty.ObjectVal(map[string]cty.Value{"index": planValue(x)})}
	case string:
		return map[string]cty.Value{"each": cty.ObjectVal(map[string]cty.Value{"key": cty.StringVal(x), "value": cty.DynamicVal})}
	}
	return nil
}

// moduleSegments splits a module instance address into its calls, each
// formatted the way the model writes addresses (module.<label><key>), and
// their labels.
func moduleSegments(addr string) (segs, labels []string) {
	if addr == "" {
		return nil, nil
	}
	t, diags := hclsyntax.ParseTraversalAbs([]byte(addr), "", hcl.InitialPos)
	if diags.HasErrors() {
		return []string{addr}, []string{addr}
	}
	expectLabel := false
	for _, step := range t {
		var name string
		switch s := step.(type) {
		case hcl.TraverseRoot:
			name = s.Name
		case hcl.TraverseAttr:
			name = s.Name
		case hcl.TraverseIndex:
			if len(segs) > 0 {
				segs[len(segs)-1] += address.InstanceSuffix(s.Key)
			}
			continue
		}
		if expectLabel {
			segs = append(segs, address.KindModule+"."+name)
			labels = append(labels, name)
			expectLabel = false
			continue
		}
		expectLabel = name == address.KindModule
	}
	return segs, labels
}

// normalizeModuleAddr formats a module instance address the way the model
// does.
func normalizeModuleAddr(addr string) string {
	segs, _ := moduleSegments(addr)
	return strings.Join(segs, ".")
}

// moduleNames returns the call labels of a module instance address.
func moduleNames(addr string) []string {
	_, labels := moduleSegments(addr)
	return labels
}

// configPath is a module instance address without instance keys.
func configPath(addr string) string {
	names := moduleNames(addr)
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = address.KindModule + "." + n
	}
	return strings.Join(parts, ".")
}

// parentModule returns the address of the module instance calling addr.
func parentModule(addr string) string {
	segs, _ := moduleSegments(addr)
	if len(segs) < 2 {
		return ""
	}
	return strings.Join(segs[:len(segs)-1], ".")
}

func callLabel(addr string) string {
	names := moduleNames(addr)
	if len(names) == 0 {
		return ""
	}
	return names[len(names)-1]
}

func object(m map[string]any, path ...string) (map[string]any, bool) {
	for _, p := range path {
		next, ok := m[p].(map[string]any)
		if !ok {
			return nil, false
		}
		m = next
	}
	return m, m != nil
}

func list(m map[string]any, key string) []any {
	l, _ := m[key].([]any)
	return l
}

func stringList(v any) []string {
	var out []string
	l, _ := v.([]any)
	for _, e := range l {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// namesOnly drops the list indexes of a dot-joined path.
func namesOnly(path string) string {
	parts := strings.Split(path, ".")
	out := parts[:0]
	for _, p := range parts {
		if _, err := strconv.Atoi(p); err != nil {
			out = append(out, p)
		}
	}
	return strings.Join(out, ".")
}
