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
	ddMetaKey     = "_dd_meta"
	referencesKey = "references"
)

// resourceMeta is the _dd_meta object: address string, root_modules []interface{} of strings
// and, when non-nil, references.
func resourceMeta(addr string, roots []string, references map[string]interface{}) map[string]interface{} {
	rootList := make([]interface{}, len(roots))
	for i, r := range roots {
		rootList[i] = r
	}
	meta := map[string]interface{}{"address": addr, "root_modules": rootList}
	if references != nil {
		meta[referencesKey] = references
	}
	return meta
}

// stampWrittenMeta adds _dd_meta to every name-keyed block of the resource,
// data and ephemeral sections of doc (replacing any value already there).
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
				addr := address.Instance("", address.Block{Kind: s.kind, Type: typ, Name: name}, "")
				block[ddMetaKey] = resourceMeta(addr, []string{scope.RootModule}, nil)
			}
		}
	}
}

// stampPlanMeta adds _dd_meta to each plan resource and data object, with the
// address Terraform computed for it and, when traced, its references
// (replacing any value already there).
func stampPlanMeta(doc map[string]interface{}, addresses map[[2]string]string, references map[[2]string]interface{}, root string) {
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
			refs, _ := references[k].(map[string]interface{})
			block[ddMetaKey] = resourceMeta(addr, []string{root}, refs)
		}
	}
}
