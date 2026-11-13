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

// declaresTargetedResource reports whether any scanned Terraform file declares
// a resource or data type some rule can match by name.
func declaresTargetedResource(files model.FileMetadatas, targets *ruleTargets) bool {
	if targets == nil {
		return true
	}
	for _, f := range files {
		if f == nil || !isTerraformConfigFile(f) {
			continue
		}
		for _, key := range [...]string{address.KindResource, address.KindData, address.KindEphemeral} {
			blocks, ok := asStringMap(f.Document[key])
			if !ok {
				continue
			}
			for typ := range blocks {
				// Ephemeral rules name the type with its namespace prefix.
				if targets.matches(typ) || targets.matches(address.EphemeralPrefix+typ) {
					return true
				}
			}
		}
	}
	return false
}

// blockSections are the document sections that hold typed, named blocks, with
// the prefix their type carries where the sections share a namespace.
var blockSections = [...]struct{ section, prefix string }{
	{address.KindResource, ""},
	{address.KindData, address.DataPrefix},
	{address.KindEphemeral, address.EphemeralPrefix},
}

// writesExpansion reports whether a parsed block writes count or for_each,
// which its document leaves out but its line table records.
func writesExpansion(block interface{}) bool {
	attrs, _ := asStringMap(block)
	has := func(key string) bool {
		switch lines := attrs["_dd_lines"].(type) {
		case map[string]model.LineObject:
			_, ok := lines[key]
			return ok
		case map[string]interface{}:
			_, ok := lines[key]
			return ok
		}
		return false
	}
	return has("_dd_count") || has("_dd_for_each")
}

// declaresExpandedBlock reports whether any scanned Terraform file declares a
// block some rule can match by name with count or for_each, which may expand
// to no instance.
func declaresExpandedBlock(files model.FileMetadatas, targets *ruleTargets) bool {
	if targets == nil {
		return false
	}
	for _, f := range files {
		if f == nil || !isTerraformConfigFile(f) {
			continue
		}
		for _, bs := range blockSections {
			blocks, _ := asStringMap(f.Document[bs.section])
			for typ, byName := range blocks {
				if !targets.matches(typ) && !targets.matches(bs.prefix+typ) {
					continue
				}
				names, _ := asStringMap(byName)
				for _, block := range names {
					if writesExpansion(block) {
						return true
					}
				}
			}
		}
	}
	return false
}

// declaresLocalModuleCall reports whether any scanned Terraform file calls a
// module by a local path. Terraform reads a source starting with "./", "../"
// or "/" from the filesystem; anything else is a registry or remote source.
// A scan whose rules target no declared resource type still models the layout
// when files call local modules: expansion changes what the documents hold,
// and a module directory the scan was not given is an escalation request
// recorded when the model reads it. Plain .json files the scan recognizes as
// Terraform configuration by content count like .tf files: the model reads
// them, so their module calls escalate the same way.
func declaresLocalModuleCall(files model.FileMetadatas) bool {
	for _, f := range files {
		if f == nil || !isTerraformConfigFile(f) {
			continue
		}
		modules, _ := asStringMap(f.Document["module"])
		for _, body := range modules {
			attrs, _ := asStringMap(body)
			source, _ := attrs["source"].(string)
			if source == "" {
				continue
			}
			if strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../") || strings.HasPrefix(source, "/") {
				return true
			}
		}
	}
	return false
}
