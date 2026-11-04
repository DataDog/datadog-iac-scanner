/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/blockmeta"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
)

const (
	ddPrefix      = "_dd_"
	ddMetaKey     = "_dd_meta"
	referencesKey = "references"
	unknownKey    = "unknown"
	ambiguousKey  = "ambiguous"
	configuredKey = "configured"
	providerKey   = "provider"
)

// blockMetaExtras holds the optional _dd_meta entries of a block, each nil or
// empty when absent.
type blockMetaExtras struct {
	references, unknown, ambiguous, configured map[string]interface{}
	// provider is the provider configuration the block uses, in root module
	// terms.
	provider string
}

// resourceMeta is the _dd_meta object: the address and the non-nil extras.
// Roots stay on the engine. A rule sees one root's documents, so metadata
// does not list them.
func resourceMeta(addr string, extras blockMetaExtras) map[string]interface{} {
	meta := map[string]interface{}{"address": addr}
	extras.writeTo(meta)
	return meta
}

// writeTo sets the non-nil extras in meta and deletes the others.
func (e blockMetaExtras) writeTo(meta map[string]interface{}) {
	for _, entry := range [...]struct {
		key   string
		value map[string]interface{}
	}{
		{referencesKey, e.references},
		{unknownKey, e.unknown},
		{ambiguousKey, e.ambiguous},
		{configuredKey, e.configured},
	} {
		if entry.value != nil {
			meta[entry.key] = entry.value
		} else {
			delete(meta, entry.key)
		}
	}
	if e.provider != "" {
		meta[providerKey] = e.provider
	} else {
		delete(meta, providerKey)
	}
}

// configuredShape is the _dd_meta.configured of an evaluated block.
func configuredShape(r *tfeval.ResolvedResource, doc map[string]interface{}) map[string]interface{} {
	return blockmeta.Configured(r.Body, doc, r.DynamicCounts.Blocks)
}

// resolvedProvider is the address of the provider configuration r uses: its
// provider meta-argument or its type's default configuration, mapped through
// the providers argument of every call up to the module declaring it. That is
// "aws" or "aws.west" for a root module configuration and, as a plan keys it,
// "module.a.module.b:aws" for one declared by module.a.module.b. It is empty
// when the meta-argument is not a configuration reference or a call does not
// pass the alias r uses.
func resolvedProvider(r *tfeval.ResolvedResource) string {
	addr := blockmeta.DefaultProvider(r.Type)
	if r.Body != nil {
		addr = blockmeta.BodyProvider(r.Body, r.Type)
	}
	if addr == "" {
		return ""
	}
	scope := r.Scope
	for i := len(r.CallChain) - 1; i >= 0; i-- {
		if scope != nil && blockmeta.Declares(scope.Bodies, addr) {
			return blockmeta.ModuleProvider(moduleConfigPath(r.CallChain[:i+1]), addr)
		}
		next, ok := blockmeta.Inherit(addr, blockmeta.ProvidersMap(r.CallChain[i].Body))
		if !ok {
			return ""
		}
		addr, scope = next, r.CallChain[i].Caller
	}
	return addr
}

// moduleConfigPath is the config path of the module chain calls, module.a.module.b.
func moduleConfigPath(chain []tfeval.CallSite) string {
	var b strings.Builder
	for i, call := range chain {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString("module.")
		b.WriteString(call.ModuleName)
	}
	return b.String()
}

// mergeEvaluated overwrites dst's content keys with src's in place, in a
// block's nested blocks too. Keys with the _dd_ prefix in dst are never
// touched. With replace, src is the whole evaluated body: a content key it
// lacks, an attribute evaluated to null or a dynamic template it rendered, is
// deleted from dst; otherwise dst keys src lacks stay.
func mergeEvaluated(dst, src map[string]interface{}, replace bool) {
	if replace {
		for k := range dst {
			if _, kept := src[k]; !kept && !strings.HasPrefix(k, ddPrefix) {
				delete(dst, k)
			}
		}
	}
	for k, sv := range src {
		if strings.HasPrefix(k, ddPrefix) {
			continue
		}
		dv := dst[k]
		if holdsFilterExpr(dv) {
			continue
		}
		if dm, ok := asStringMap(dv); ok {
			if sm, ok := asStringMap(sv); ok {
				mergeEvaluated(dm, sm, replace)
				continue
			}
		}
		if dl, ok := dv.([]interface{}); ok {
			if sl, ok := sv.([]interface{}); ok && mergeBlockLists(dl, sl, replace) {
				continue
			}
		}
		dst[k] = sv
	}
}

// holdsFilterExpr reports whether v is a filter the runner sink resolved: an
// object, or its JSON text, holding _dd_filter_expr.
func holdsFilterExpr(v interface{}) bool {
	const key = "_dd_filter_expr"
	if m, ok := asStringMap(v); ok {
		_, found := m[key]
		return found
	}
	s, ok := v.(string)
	return ok && strings.HasPrefix(s, `{"`+key+`"`)
}

// mergeBlockLists merges src into dst element-wise when both are lists of
// maps of equal length, reporting whether it did.
func mergeBlockLists(dst, src []interface{}, replace bool) bool {
	if len(dst) != len(src) {
		return false
	}
	for i := range dst {
		if _, ok := asStringMap(dst[i]); !ok {
			return false
		}
		if _, ok := asStringMap(src[i]); !ok {
			return false
		}
	}
	for i := range dst {
		dm, _ := asStringMap(dst[i])
		sm, _ := asStringMap(src[i])
		mergeEvaluated(dm, sm, replace)
	}
	return true
}

// stampWrittenMeta adds _dd_meta to every name-keyed block of the resource,
// data, ephemeral, module and output sections of doc, keeping what the
// parser recorded from the written block: its unknown values and, for a
// resource, its provider and configured shape.
func stampWrittenMeta(doc map[string]interface{}) {
	sections := [...]struct {
		key, kind string
		typed     bool
	}{
		{"resource", address.KindResource, true},
		{"data", address.KindData, true},
		{ephemeralSection, address.KindEphemeral, true},
		{moduleCallRoot, address.KindModule, false},
		{outputSection, address.KindOutput, false},
	}
	for _, s := range sections {
		byType, ok := asStringMap(doc[s.key])
		if !ok {
			continue
		}
		if !s.typed {
			stampBlocks(byType, func(name string) string {
				return address.Instance("", address.Block{Kind: s.kind, Name: name}, "")
			})
			continue
		}
		for typ, typeBlocksRaw := range byType {
			if isParserBookkeepingKey(typ) {
				continue
			}
			typeBlocks, ok := asStringMap(typeBlocksRaw)
			if !ok {
				continue
			}
			stampBlocks(typeBlocks, func(name string) string {
				return address.Instance("", address.Block{Kind: s.kind, Type: typ, Name: name}, "")
			})
		}
	}
}

// stampProviderMeta sets the _dd_meta of the provider blocks of each HCL file
// that stands for its own root only: the block's address and, as provider,
// the key a resource using it carries in _dd_meta.provider, "aws" or
// "aws.west". A file another root reaches as a module is in several root
// inputs as one document, and its blocks name a different configuration in
// each, so its provider blocks get no key and its blocks keep no
// _dd_meta.provider.
func stampProviderMeta(files model.FileMetadatas, docRoots map[string][]string) {
	for _, f := range files {
		if f == nil || f.Kind != model.KindTerraform || f.TerraformScope == nil || isSyntheticTerraformDoc(f) {
			continue
		}
		own := ownRootOnly(docRoots[f.ID], f.TerraformScope.RootModule)
		if !own {
			dropWrittenProviders(f.Document)
		}
		providers, _ := asStringMap(f.Document[providerSection])
		for typ, raw := range providers {
			if isParserBookkeepingKey(typ) {
				continue
			}
			entries, ok := raw.([]interface{})
			if !ok {
				entries = []interface{}{raw}
			}
			for _, entry := range entries {
				if block, ok := asStringMap(entry); ok {
					stampProviderBlock(block, typ, own)
				}
			}
		}
	}
}

// stampProviderBlock sets the address and key of one provider block of type
// typ, or, when own is false or its alias is not known, removes its key.
func stampProviderBlock(block map[string]interface{}, typ string, own bool) {
	meta, _ := asStringMap(block[ddMetaKey])
	if meta == nil {
		meta = map[string]interface{}{}
	}
	delete(meta, providerKey)
	if alias, literal := providerBlockAlias(block); own && literal {
		meta["address"] = address.ProviderAddr(typ, alias)
		meta[providerKey] = address.ProviderKey(typ, alias)
	}
	if len(meta) > 0 {
		block[ddMetaKey] = meta
	}
}

// ownRootOnly reports whether roots, a document's roots, is at most own.
func ownRootOnly(roots []string, own string) bool {
	if len(roots) == 0 {
		return false
	}
	for _, r := range roots {
		if r != own {
			return false
		}
	}
	return true
}

// providerBlockAlias is the alias of a provider block, "" for the default
// configuration. literal is false when the alias is not a known string.
func providerBlockAlias(block map[string]interface{}) (alias string, literal bool) {
	raw, hasAlias := block["alias"]
	if !hasAlias {
		return "", true
	}
	alias, ok := raw.(string)
	if !ok || alias == "" || isUnknownValue(block, "alias") {
		return "", false
	}
	return alias, true
}

// isUnknownValue reports whether the parser marked attr of block unknown.
func isUnknownValue(block map[string]interface{}, attr string) bool {
	meta, _ := asStringMap(block[ddMetaKey])
	unknown, _ := asStringMap(meta[unknownKey])
	marked, _ := unknown[attr].(bool)
	return marked
}

// dropWrittenProviders removes _dd_meta.provider from the resource, data and
// ephemeral blocks of doc.
func dropWrittenProviders(doc model.Document) {
	for _, section := range [...]string{"resource", "data", ephemeralSection} {
		byType, _ := asStringMap(doc[section])
		for _, typeBlocks := range byType {
			byName, _ := asStringMap(typeBlocks)
			for _, raw := range byName {
				for _, block := range blockEntries(raw) {
					if meta, ok := asStringMap(block[ddMetaKey]); ok {
						delete(meta, providerKey)
					}
				}
			}
		}
	}
}

// blockEntries is the map form of one or more blocks under a name.
func blockEntries(raw interface{}) []map[string]interface{} {
	if block, ok := asStringMap(raw); ok {
		return []map[string]interface{}{block}
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	out := make([]map[string]interface{}, 0, len(list))
	for _, entry := range list {
		if block, ok := asStringMap(entry); ok {
			out = append(out, block)
		}
	}
	return out
}

// stampBlocks sets the _dd_meta of every block of byName, addressed by addr.
func stampBlocks(byName map[string]interface{}, addr func(name string) string) {
	for name, raw := range byName {
		if isParserBookkeepingKey(name) {
			continue
		}
		block, ok := asStringMap(raw)
		if !ok {
			continue
		}
		var extras blockMetaExtras
		if prev, ok := asStringMap(block[ddMetaKey]); ok {
			extras.unknown, _ = asStringMap(prev[unknownKey])
			extras.configured, _ = asStringMap(prev[configuredKey])
			extras.provider, _ = prev[providerKey].(string)
		}
		block[ddMetaKey] = resourceMeta(addr(name), extras)
	}
}
