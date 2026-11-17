/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package project

import (
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/zclconf/go-cty/cty"
)

// CrossIndex holds the companions of evidence roots that name a target by a
// written literal (3.8), for the evaluation of the other roots. A first pass
// adds every evidence root; the second pass projects each root with it.
type CrossIndex struct {
	// byKey: companion type -> path -> value -> evidence.
	byKey map[string]map[string]map[string][]*Located
}

// NewCrossIndex starts an empty index.
func NewCrossIndex() *CrossIndex {
	return &CrossIndex{byKey: map[string]map[string]map[string][]*Located{}}
}

// CrossMatch is a cross-root match used by an evaluation: Target is named by
// Evidence, a block of another root.
type CrossMatch struct {
	Target, Evidence *Located
}

// Add indexes the certainly instantiated companions of a projection. The
// index keeps the model block, not its projected term: the term is built
// when a later root actually matches, and the projection can be released.
func (x *CrossIndex) Add(pr *Projection) {
	if pr.rel == nil {
		return
	}
	for _, byType := range pr.rel.companions {
		for typ, byPath := range byType {
			for path, byValue := range byPath {
				for value, list := range byValue {
					for _, c := range list {
						loc := pr.Blocks[c.id]
						if !c.certain || loc == nil {
							continue
						}
						saved := *loc
						saved.Term = nil
						detach(&saved)
						m := nested(x.byKey, typ, path)
						m[value] = append(m[value], &saved)
					}
				}
			}
		}
	}
}

// detach copies the evidence block, its instance and its provider onto a
// module that holds only their address, so the index keeps no other block
// of the evidence root alive once that root is dropped. The native syntax
// goes too: the ranges snapshot the projection built answers every location
// question about the block, so the index does not pin the parsed file.
func detach(loc *Located) {
	if loc.Block == nil {
		return
	}
	b := detachedBlock(loc.Block)
	if loc.Block.ProviderBlock != nil {
		b.ProviderBlock = detachedBlock(loc.Block.ProviderBlock)
		b.ProviderBlock.Instances = detachedInstances(b.ProviderBlock, loc.Block.ProviderBlock.Instances)
	}
	if loc.inst != nil {
		inst := *loc.inst
		inst.Block = b
		inst.Refs = nil
		loc.inst = &inst
		b.Instances = []*model.Instance{loc.inst}
	}
	loc.Block = b
}

func detachedBlock(b *model.Block) *model.Block {
	out := *b
	out.Syntax = nil
	if b.Module != nil {
		out.Module = &model.Module{Address: b.Module.Address, Dir: b.Module.Dir}
	}
	return &out
}

func detachedInstances(b *model.Block, insts []*model.Instance) []*model.Instance {
	out := make([]*model.Instance, len(insts))
	for i, inst := range insts {
		c := *inst
		c.Block = b
		c.Refs = nil
		out[i] = &c
	}
	return out
}

// Merge adds the evidence of other to x.
func (x *CrossIndex) Merge(other *CrossIndex) {
	if other == nil {
		return
	}
	for typ, byPath := range other.byKey {
		for path, byValue := range byPath {
			m := nested(x.byKey, typ, path)
			for value, list := range byValue {
				m[value] = append(m[value], list...)
			}
		}
	}
}

// Empty reports an index without evidence.
func (x *CrossIndex) Empty() bool {
	return x == nil || len(x.byKey) == 0
}

func (x *CrossIndex) lookup(typ, path, value string) []*Located {
	if x == nil {
		return nil
	}
	return x.byKey[typ][path][value]
}

// defaultPartition is the partition of a region that names no other.
const defaultPartition = "aws"

// crossScope reports whether evidence in another root may name target: S3
// bucket names are global per partition; other names need the same provider
// configuration, known on both sides.
func crossScope(target, evidence *Located) bool {
	ts, tp, tok := providerScope(target)
	es, ep, eok := providerScope(evidence)
	if globalLiteralTypes[target.Type] {
		return tp != "" && tp == ep
	}
	return tok && eok && ts == es
}

// providerScope is the provider configuration of a block as a comparable
// string, and its partition. ok is false when the configuration is absent or
// not known.
func providerScope(loc *Located) (scope, partition string, ok bool) {
	b := loc.Block
	if b == nil || b.ProviderBlock == nil || len(b.ProviderBlock.Instances) == 0 {
		return "", defaultPartition, false
	}
	attrs := b.ProviderBlock.Instances[0].Attrs
	region, known := knownString(attrs, "region")
	if !known {
		return "", "", false
	}
	partition = defaultPartition
	switch {
	case strings.HasPrefix(region, "cn-"):
		partition = "aws-cn"
	case strings.HasPrefix(region, "us-gov-"):
		partition = "aws-us-gov"
	}
	parts := []string{b.ProviderBlock.Type, region}
	for _, name := range []string{"profile", "alias"} {
		s, known := knownString(attrs, name)
		if !known {
			return "", partition, false
		}
		parts = append(parts, s)
	}
	for name := range attrs {
		if strings.HasPrefix(name, "assume_role") {
			return "", partition, false
		}
	}
	// Any other attribute may select the account or the endpoint that serves
	// it (keys, tokens, credential files, allowed account ids, endpoints):
	// two configurations are the same only when each is known and equal.
	for _, name := range sortedKeys(attrs) {
		if scopeNeutral[name] {
			continue
		}
		v, _ := attrs[name].UnmarkDeep()
		if v.IsNull() {
			continue
		}
		if !v.IsWhollyKnown() {
			return "", partition, false
		}
		parts = append(parts, name+"="+v.GoString())
	}
	return strings.Join(parts, "\x00"), partition, true
}

// scopeNeutral are the provider attributes that neither select an account nor
// the endpoint serving it. region, profile and alias are compared on their
// own.
var scopeNeutral = map[string]bool{
	"region": true, "profile": true, "alias": true,
	"default_tags": true, "ignore_tags": true,
	"max_retries": true, "retry_mode": true,
	"skip_credentials_validation": true, "skip_metadata_api_check": true,
	"skip_region_validation": true, "skip_requesting_account_id": true,
	"s3_use_path_style": true, "s3_us_east_1_regional_endpoint": true,
	"use_fips_endpoint": true, "use_dualstack_endpoint": true,
	"http_proxy": true, "https_proxy": true, "no_proxy": true,
	"insecure": true, "custom_ca_bundle": true,
}

// knownString is the string at name, "" when absent; known is false for a
// value that is unknown or not a string.
func knownString(attrs map[string]cty.Value, name string) (s string, known bool) {
	v, ok := attrs[name]
	if !ok || v.IsNull() {
		return "", true
	}
	if !v.IsKnown() || v.Type() != cty.String {
		return "", false
	}
	return v.AsString(), true
}

// crossCompanions adds the evidence of other roots that names target at the
// value s to its related list.
func (p *projector) crossCompanions(target *Located, rel literalRel, s string, related *idList) {
	for _, ev := range p.opts.Cross.lookup(rel.companion, rel.path, s) {
		if ev.Root == target.Root || !crossScope(target, ev) {
			continue
		}
		id := blockID(ev)
		related.add(id)
		local, seen := p.located[id]
		if !seen {
			// The index entry is shared by every projection: build the term,
			// and its _dd.nested entry, on this projection's own copy.
			c := *ev
			c.Term = nil
			p.materialize(&c)
			local = &c
			p.located[id] = local
			p.byID = append(p.byID, ast.Item(p.key(id), local.Term))
			p.external[id] = true
		}
		p.cross = append(p.cross, CrossMatch{Target: target, Evidence: local})
	}
}

func blockID(loc *Located) string {
	if loc.ID != "" {
		return loc.ID
	}
	return loc.Root + "/" + loc.Address
}

// materialize builds the projected term of an evidence block the index kept
// without one. The provider id recorded with the block is reused, so the
// term matches the one the evidence root projected.
func (p *projector) materialize(loc *Located) {
	if loc.Term != nil || loc.Block == nil || loc.inst == nil {
		return
	}
	if loc.provider != "" && loc.Block.ProviderBlock != nil && len(loc.Block.ProviderBlock.Instances) > 0 {
		p.ids[loc.Block.ProviderBlock.Instances[0]] = loc.provider
	}
	shared := p.sharedMeta(&model.Root{ID: loc.Root}, loc.Block)
	nonliteral := make([]*ast.Term, 0, len(loc.Block.Nonliteral))
	for _, path := range loc.Block.Nonliteral {
		nonliteral = append(nonliteral, ast.StringTerm(path))
	}
	nonliteralTerm := ast.ArrayTerm(nonliteral...)
	sharedDerived := ast.ObjectTerm(
		ast.Item(p.key("template"), p.emptyObject),
		ast.Item(p.key("json"), p.emptyObject),
		ast.Item(p.key("nonliteral"), nonliteralTerm),
	)
	loc.Term, _, _ = p.instanceTerm(loc.inst, blockID(loc), instanceKey(loc.Block, loc.inst), shared, sharedDerived, nonliteralTerm, nil)
}
