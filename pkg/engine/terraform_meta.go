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
)

const (
	ddPrefix      = "_dd_"
	ddMetaKey     = "_dd_meta"
	referencesKey = "references"
	unknownKey    = "unknown"
)

// blockMetaExtras holds the optional _dd_meta entries of a block, each nil when absent.
type blockMetaExtras struct{ references, unknown map[string]interface{} }

// resourceMeta is the _dd_meta object: address string, root_modules []interface{} of strings
// and the non-nil extras.
func resourceMeta(addr string, roots []string, extras blockMetaExtras) map[string]interface{} {
	rootList := make([]interface{}, len(roots))
	for i, r := range roots {
		rootList[i] = r
	}
	meta := map[string]interface{}{"address": addr, "root_modules": rootList}
	if extras.references != nil {
		meta[referencesKey] = extras.references
	}
	if extras.unknown != nil {
		meta[unknownKey] = extras.unknown
	}
	return meta
}

// mergeEvaluated overwrites dst's content keys with src's in place. Keys with
// the _dd_ prefix in dst are never touched; dst keys src lacks stay, except
// dynamic templates of a block src renders.
func mergeEvaluated(dst, src map[string]interface{}) {
	dynamic, hasDynamic := asStringMap(dst["dynamic"])
	if _, rendered := src["dynamic"]; rendered {
		hasDynamic = false
	}
	for k, sv := range src {
		if strings.HasPrefix(k, ddPrefix) {
			continue
		}
		if hasDynamic {
			delete(dynamic, k)
		}
		dv := dst[k]
		if holdsFilterExpr(dv) {
			continue
		}
		if dm, ok := asStringMap(dv); ok {
			if sm, ok := asStringMap(sv); ok {
				mergeEvaluated(dm, sm)
				continue
			}
		}
		if dl, ok := dv.([]interface{}); ok {
			if sl, ok := sv.([]interface{}); ok && mergeBlockLists(dl, sl) {
				continue
			}
		}
		dst[k] = sv
	}
	if hasDynamic && len(dynamic) == 0 {
		delete(dst, "dynamic")
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

// dropDynamicTemplates deletes block's dynamic templates of the given types,
// and the dynamic key once it holds none.
func dropDynamicTemplates(block map[string]interface{}, types map[string]bool) {
	dynamic, ok := asStringMap(block["dynamic"])
	if !ok || len(types) == 0 {
		return
	}
	for typ := range types {
		delete(dynamic, typ)
	}
	if len(dynamic) == 0 {
		delete(block, "dynamic")
	}
}

// mergeBlockLists merges src into dst element-wise when both are lists of
// maps of equal length, reporting whether it did.
func mergeBlockLists(dst, src []interface{}) bool {
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
		mergeEvaluated(dm, sm)
	}
	return true
}

// stampWrittenMeta adds _dd_meta to every name-keyed block of the resource,
// data and ephemeral sections of doc, keeping only the unknown values the
// converter recorded in any value already there.
func stampWrittenMeta(doc map[string]interface{}, scope *model.TerraformScope) {
	sections := [...]struct{ key, kind string }{
		{"resource", address.KindResource},
		{"data", address.KindData},
		{ephemeralSection, address.KindEphemeral},
	}
	for _, s := range sections {
		byType, ok := asStringMap(doc[s.key])
		if !ok {
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
			for name, raw := range typeBlocks {
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
				}
				addr := address.Instance("", address.Block{Kind: s.kind, Type: typ, Name: name}, "")
				block[ddMetaKey] = resourceMeta(addr, []string{scope.RootModule}, extras)
			}
		}
	}
}

// stampPlanMeta adds _dd_meta to each plan resource and data object, with the
// address Terraform computed for it and its extras (replacing any value
// already there).
func stampPlanMeta(doc map[string]interface{}, addresses map[[2]string]string, extras map[[2]string]blockMetaExtras, root string) {
	for k, addr := range addresses {
		section, typ := resourceSection, k[0]
		if dataType, ok := strings.CutPrefix(typ, "data."); ok {
			section, typ = dataRoot, dataType
		}
		byType, ok := asStringMap(doc[section])
		if !ok {
			continue
		}
		byKey, ok := asStringMap(byType[typ])
		if !ok {
			continue
		}
		if block, ok := asStringMap(byKey[k[1]]); ok {
			block[ddMetaKey] = resourceMeta(addr, []string{root}, extras[k])
		}
	}
}
