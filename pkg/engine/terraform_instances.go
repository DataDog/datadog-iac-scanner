/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

func terraformInstanceFor(file *model.FileMetadata, resourceType, name string) (model.TerraformInstance, bool) {
	_, instance, ok := terraformInstanceKeyFor(file, resourceType, name)
	return instance, ok
}

func terraformInstanceKeyFor(
	file *model.FileMetadata, resourceType, name string,
) (model.TerraformInstanceKey, model.TerraformInstance, bool) {
	if file == nil || name == "" || len(file.TerraformInstances) == 0 {
		return model.TerraformInstanceKey{}, model.TerraformInstance{}, false
	}
	kind := tfSectionResource
	typ := resourceType
	explicitKind := false
	if rest, ok := strings.CutPrefix(typ, dataRoot+"."); ok {
		kind, typ, explicitKind = dataRoot, rest, true
	} else if rest, ok := strings.CutPrefix(typ, tfSectionResource+"."); ok {
		kind, typ, explicitKind = tfSectionResource, rest, true
	}
	key := model.TerraformInstanceKey{Kind: kind, Type: typ, Name: name}
	if instance, ok := file.TerraformInstances[key]; ok {
		return key, instance, true
	}
	// Legacy rules often report a data block's type without the `data.` prefix.
	// Prefer a resource when both namespaces contain the same type/name, which
	// preserves the historical interpretation, then fall back to data.
	if !explicitKind {
		candidate := model.TerraformInstanceKey{Kind: dataRoot, Type: typ, Name: name}
		if instance, ok := file.TerraformInstances[candidate]; ok {
			return candidate, instance, true
		}
	}
	return model.TerraformInstanceKey{}, model.TerraformInstance{}, false
}

type terraformInstanceSelector struct {
	start, end  int
	written     string
	replacement string
}

func terraformInstanceFromSearchKey(
	file *model.FileMetadata, resourceType, resourceName, searchKey string,
) (model.TerraformInstanceKey, terraformInstanceSelector, bool) {
	if file == nil || len(file.TerraformInstances) == 0 {
		return model.TerraformInstanceKey{}, terraformInstanceSelector{}, false
	}
	kind, typ := tfSectionResource, resourceType
	explicitKind := false
	for _, candidate := range []string{dataRoot, tfSectionResource} {
		if rest, ok := strings.CutPrefix(typ, candidate+"."); ok {
			kind, typ, explicitKind = candidate, rest, true
			break
		}
	}
	if !explicitKind {
		for _, candidate := range []string{dataRoot, tfSectionResource} {
			if hasTerraformSelectorPrefix(searchKey, candidate, typ) {
				kind, explicitKind = candidate, true
				break
			}
		}
	}
	if resourceName != "" {
		if key, instance, ok := terraformInstanceKeyFor(file, resourceType, resourceName); ok {
			if selector, matched := terraformInstanceSelectorFor(searchKey, key, instance); matched {
				return key, selector, true
			}
		}
	}
	kinds := []string{kind}
	if !explicitKind {
		kinds = []string{tfSectionResource, dataRoot}
	}
	for _, candidateKind := range kinds {
		if key, selector, ok := terraformInstanceInNamespace(file, candidateKind, typ, searchKey); ok {
			return key, selector, true
		}
	}
	return model.TerraformInstanceKey{}, terraformInstanceSelector{}, false
}

func terraformInstanceInNamespace(
	file *model.FileMetadata, kind, typ, searchKey string,
) (model.TerraformInstanceKey, terraformInstanceSelector, bool) {
	for key, instance := range file.TerraformInstances {
		if key.Kind != kind || key.Type != typ {
			continue
		}
		if selector, matched := terraformInstanceSelectorFor(searchKey, key, instance); matched {
			return key, selector, true
		}
	}
	return model.TerraformInstanceKey{}, terraformInstanceSelector{}, false
}

func hasTerraformSelectorPrefix(searchKey, kind, typ string) bool {
	return strings.HasPrefix(searchKey, kind+"."+typ+"[") ||
		strings.HasPrefix(searchKey, kind+"."+typ+".")
}

func terraformInstanceSelectorFor(
	searchKey string, key model.TerraformInstanceKey, instance model.TerraformInstance,
) (terraformInstanceSelector, bool) {
	for _, prefix := range []string{key.Kind + "." + key.Type + "[", key.Type + "["} {
		if !strings.HasPrefix(searchKey, prefix) {
			continue
		}
		start := len(prefix)
		for _, selector := range terraformInstanceSelectors(key.Name, instance.Label) {
			if strings.HasPrefix(searchKey[start:], selector.written+"]") {
				return terraformInstanceSelector{
					start: start, end: start + len(selector.written), written: selector.written, replacement: selector.label,
				}, true
			}
		}
	}
	// Some legacy rules build selectors with dot notation instead of brackets.
	for _, prefix := range []string{key.Kind + "." + key.Type + ".", key.Type + "."} {
		if !strings.HasPrefix(searchKey, prefix) {
			continue
		}
		start := len(prefix)
		for _, selector := range terraformInstanceSelectors(key.Name, instance.Label) {
			remainder := searchKey[start:]
			if remainder == selector.written || strings.HasPrefix(remainder, selector.written+".") {
				return terraformInstanceSelector{
					start: start, end: start + len(selector.written), written: selector.written, replacement: selector.label,
				}, true
			}
		}
	}
	return terraformInstanceSelector{}, false
}

func normalizeTerraformInstanceSearchKey(file *model.FileMetadata, resourceType, resourceName, searchKey string) string {
	_, selector, ok := terraformInstanceFromSearchKey(file, resourceType, resourceName, searchKey)
	if !ok {
		return searchKey
	}
	return replaceTerraformInstanceSelector(searchKey, selector)
}

func replaceTerraformInstanceSelector(searchKey string, selector terraformInstanceSelector) string {
	if selector.written == selector.replacement {
		return searchKey
	}
	return searchKey[:selector.start] + selector.replacement + searchKey[selector.end:]
}

func terraformInstanceSelectors(name, label string) []struct{ written, label string } {
	quoted := strconv.Quote(name)
	quotedLabel := strconv.Quote(label)
	return []struct{ written, label string }{
		{name, label},
		{"{{" + name + "}}", "{{" + label + "}}"},
		{quoted, quotedLabel},
		{"'" + name + "'", "'" + label + "'"},
		{"{{" + quoted + "}}", "{{" + quotedLabel + "}}"},
		{"{{'" + name + "'}}", "{{'" + label + "'}}"},
	}
}

func terraformInstanceFromPath(
	file *model.FileMetadata, path model.SourcePath,
) (model.TerraformInstanceKey, model.TerraformInstance, bool) {
	if file == nil || len(path) < 3 || path[0].IsIndex || path[1].IsIndex || path[2].IsIndex {
		return model.TerraformInstanceKey{}, model.TerraformInstance{}, false
	}
	key := model.TerraformInstanceKey{Kind: path[0].Key, Type: path[1].Key, Name: path[2].Key}
	if key.Kind != tfSectionResource && key.Kind != dataRoot {
		return model.TerraformInstanceKey{}, model.TerraformInstance{}, false
	}
	instance, ok := file.TerraformInstances[key]
	return key, instance, ok
}

func normalizeTerraformInstancePath(file *model.FileMetadata, path model.SourcePath) model.SourcePath {
	if len(path) == 0 {
		return path
	}
	key, instance, ok := terraformInstanceFromPath(file, path)
	if !ok || key.Name == instance.Label {
		return path
	}
	copyPath := append(model.SourcePath(nil), path...)
	copyPath[2].Key = instance.Label
	return copyPath
}

func normalizeTerraformFinding(
	file *model.FileMetadata,
	resourceType, resourceName, writtenKey string,
	sourcePath model.SourcePath,
) (normalizedResourceName, normalizedWrittenKey string, normalizedSourcePath model.SourcePath) {
	if file == nil || len(file.TerraformInstances) == 0 {
		return resourceName, writtenKey, sourcePath
	}
	if key, instance, ok := terraformInstanceFromPath(file, sourcePath); ok {
		sourcePath = normalizeTerraformInstancePath(file, sourcePath)
		if selector, matched := terraformInstanceSelectorFor(writtenKey, key, instance); matched {
			writtenKey = replaceTerraformInstanceSelector(writtenKey, selector)
		}
		if resourceName == key.Name {
			resourceName = instance.Label
		}
		return resourceName, writtenKey, sourcePath
	}
	writtenKey = normalizeTerraformInstanceSearchKey(file, resourceType, resourceName, writtenKey)
	if instance, ok := terraformInstanceFor(file, resourceType, resourceName); ok {
		resourceName = instance.Label
	}
	return resourceName, writtenKey, sourcePath
}

func terraformInstanceOccurrencePath(
	file *model.FileMetadata, resourceType, resourceName, searchKey string, sourcePath model.SourcePath,
) (model.SourcePath, model.TerraformBlock, bool) {
	if key, _, ok := terraformInstanceFromPath(file, sourcePath); ok {
		return model.SourcePath{{Key: key.Kind}, {Key: key.Type}, {Key: key.Name}}, model.TerraformBlock(key), true
	}
	key, _, ok := terraformInstanceFromSearchKey(file, resourceType, resourceName, searchKey)
	if !ok {
		key, _, ok = terraformInstanceKeyFor(file, resourceType, resourceName)
		if !ok {
			return nil, model.TerraformBlock{}, false
		}
	}
	path := model.SourcePath{{Key: key.Kind}, {Key: key.Type}, {Key: key.Name}}
	return path, model.TerraformBlock(key), true
}
