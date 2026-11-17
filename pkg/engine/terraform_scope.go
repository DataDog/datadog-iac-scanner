/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/json"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
)

const (
	syntheticLinesField    = "_dd_lines"
	syntheticLocalsSection = "locals"
)

func (c *Inspector) stampTerraformScopes(files model.FileMetadatas) {
	for _, f := range files {
		if f == nil || f.TerraformScope != nil {
			continue
		}
		switch f.Kind {
		case model.KindTerraformPlan:
			f.TerraformScope = &model.TerraformScope{
				RootModule: repoRelativeFile(f.FilePath, c.repoPath), PlanAddresses: json.PlanAddresses(f.Document),
			}
		case model.KindTerraform:
			lower := strings.ToLower(f.FilePath)
			if strings.HasSuffix(lower, tfpath.ExtTFVars) || strings.HasSuffix(lower, tfpath.ExtTFVarsJSON) {
				f.TerraformScope = &model.TerraformScope{RootModule: repoRelativeFile(f.FilePath, c.repoPath)}
				continue
			}
			dir := filepath.Dir(f.FilePath)
			f.TerraformScope = &model.TerraformScope{
				RootModule: repoRelativeDir(dir, c.repoPath), Blocks: documentBlocks(f.Document),
				UnresolvedInstances: unaddressableEphemeralInstances(f.Document),
			}
		}
	}
}

// unaddressableEphemeralInstances marks ephemeral blocks with count or
// for_each. The current evaluator does not materialize ephemeral instances,
// so reporting their base address would misidentify an instance.
func unaddressableEphemeralInstances(doc model.Document) map[model.TerraformBlock]bool {
	byType, ok := asStringMap(doc["ephemeral"])
	if !ok {
		return nil
	}
	var unresolved map[model.TerraformBlock]bool
	for typ, raw := range byType {
		byName, ok := asStringMap(raw)
		if !ok {
			continue
		}
		for name, rawBody := range byName {
			body, ok := asStringMap(rawBody)
			if !ok {
				continue
			}
			if _, hasCount := body["count"]; !hasCount {
				if _, hasForEach := body["for_each"]; !hasForEach {
					continue
				}
			}
			if unresolved == nil {
				unresolved = make(map[model.TerraformBlock]bool)
			}
			unresolved[model.TerraformBlock{Kind: address.KindEphemeral, Type: typ, Name: name}] = true
		}
	}
	return unresolved
}

func repoRelativeDir(dir, repoPath string) string {
	if repoPath == "" {
		return filepath.ToSlash(filepath.Clean(dir))
	}
	rel, err := filepath.Rel(filepath.Clean(repoPath), filepath.Clean(absPath(dir, repoPath)))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filepath.Base(filepath.Clean(dir))
	}
	if rel == "." {
		return "."
	}
	return filepath.ToSlash(rel)
}

// nolint:gocyclo // block inventory has separate collection shapes for resource and singleton sections.
func documentBlocks(doc model.Document) map[model.TerraformBlock]bool {
	if len(doc) == 0 {
		return nil
	}
	blocks := make(map[model.TerraformBlock]bool)
	for _, section := range []struct{ key, kind string }{
		{"resource", address.KindResource}, {"data", address.KindData}, {"ephemeral", address.KindEphemeral},
	} {
		byType, ok := asStringMap(doc[section.key])
		if !ok {
			continue
		}
		for typ, raw := range byType {
			if typ == syntheticLinesField {
				continue
			}
			byName, ok := asStringMap(raw)
			if !ok {
				blocks[model.TerraformBlock{Kind: section.kind, Type: typ}] = true
				continue
			}
			for name := range byName {
				if name != syntheticLinesField {
					blocks[model.TerraformBlock{Kind: section.kind, Type: typ, Name: name}] = true
				}
			}
		}
	}
	for _, section := range []struct{ key, kind string }{
		{"module", address.KindModule}, {"variable", address.KindVariable}, {"output", address.KindOutput},
		{"check", address.KindCheck}, {syntheticLocalsSection, address.KindLocal},
	} {
		byName, ok := asStringMap(doc[section.key])
		if !ok {
			continue
		}
		for name := range byName {
			if name != syntheticLinesField {
				blocks[model.TerraformBlock{Kind: section.kind, Name: name}] = true
			}
		}
	}
	if providers, ok := asStringMap(doc["provider"]); ok {
		for typ, raw := range providers {
			entries, ok := raw.([]interface{})
			if !ok {
				entries = []interface{}{raw}
			}
			for _, entry := range entries {
				attrs, ok := asStringMap(entry)
				if !ok {
					continue
				}
				alias, _ := attrs["alias"].(string)
				blocks[model.TerraformBlock{Kind: address.KindProvider, Type: typ, Name: alias}] = true
			}
		}
	}
	return blocks
}

func resolveTerraformBlock(scope *model.TerraformScope, resourceType, resourceName string) (address.Block, bool) {
	typ, isData := strings.CutPrefix(resourceType, address.DataPrefix)
	if typ == "" {
		return address.Block{}, false
	}
	switch typ {
	case address.KindModule, address.KindVariable, address.KindOutput, address.KindCheck, address.KindLocal, syntheticLocalsSection:
		kind := typ
		if kind == syntheticLocalsSection {
			kind = address.KindLocal
		}
		b := address.Block{Kind: kind, Name: resourceName}
		return b, blockDeclared(scope, b)
	case address.KindProvider:
		providerType, alias, hasAlias := strings.Cut(resourceName, ".")
		if !hasAlias {
			providerType, alias = resourceName, ""
		}
		b := address.Block{Kind: address.KindProvider, Type: providerType, Name: alias}
		return b, blockDeclared(scope, b)
	case address.KindTerraform, address.KindMoved, address.KindImport, address.KindRemoved:
		b := address.Block{Kind: typ, Name: resourceName}
		return b, blockDeclared(scope, b)
	}
	if ephemeralType, ok := strings.CutPrefix(typ, address.EphemeralPrefix); ok {
		b := address.Block{Kind: address.KindEphemeral, Type: ephemeralType, Name: resourceName}
		return b, blockDeclared(scope, b)
	}
	kind := address.KindResource
	if isData {
		kind = address.KindData
	}
	b := address.Block{Kind: kind, Type: typ, Name: resourceName}
	if blockDeclared(scope, b) {
		return b, true
	}
	if !isData {
		for _, fallback := range []string{address.KindData, address.KindEphemeral} {
			alt := address.Block{Kind: fallback, Type: typ, Name: resourceName}
			if blockDeclared(scope, alt) {
				return alt, true
			}
		}
	}
	return address.Block{}, false
}

func blockDeclared(scope *model.TerraformScope, b address.Block) bool {
	return scope == nil || scope.Blocks == nil || scope.Blocks[b]
}

func terraformAddressFor(file *model.FileMetadata, resourceType, resourceName, suffix string) (string, bool) {
	if file == nil || file.TerraformScope == nil {
		return "", false
	}
	scope := file.TerraformScope
	if file.Kind == model.KindTerraformPlan {
		if id, ok := scope.PlanAddresses[model.PlanResourceKey{Section: resourceType, Key: resourceName}]; ok {
			return id, true
		}
		if !strings.HasPrefix(resourceType, "data.") && !strings.HasPrefix(resourceType, "ephemeral.") {
			for _, prefix := range []string{address.DataPrefix, address.EphemeralPrefix} {
				if id, ok := scope.PlanAddresses[model.PlanResourceKey{Section: prefix + resourceType, Key: resourceName}]; ok {
					return id, true
				}
			}
		}
		return "", false
	}
	b, ok := resolveTerraformBlock(scope, resourceType, resourceName)
	if !ok {
		return "", false
	}
	if b.Kind == address.KindEphemeral && scope.UnresolvedInstances[b] {
		return "", false
	}
	return address.Instance(scope.ModuleAddress, b, suffix), true
}
