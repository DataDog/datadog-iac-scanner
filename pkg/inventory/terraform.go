/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import (
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

func itoa(n int) string { return strconv.Itoa(n) }

const platformTerraform = "terraform"

// ddLinesKey / ddDefaultKey are the Terraform converter's line-annotation keys.
const (
	ddLinesKey   = "_dd_lines"
	ddDefaultKey = "_dd__default"
)

type terraformWalker struct{}

func (terraformWalker) Platform() string { return platformTerraform }

func (terraformWalker) Kinds() []model.FileKind { return []model.FileKind{model.KindTerraform} }

func (terraformWalker) Walk(filePath string, doc model.Document) ([]Resource, bool) {
	var resources []Resource
	resources = append(resources, walkTypedBlocks(filePath, doc, "resource", BlockResource)...)
	resources = append(resources, walkTypedBlocks(filePath, doc, "data", BlockData)...)
	resources = append(resources, walkModuleBlocks(filePath, doc)...)
	return resources, true
}

// walkTypedBlocks handles the {blockKey: {type: {name: body}}} shape.
// The Terraform parser always produces the named-map form for resource and data
// blocks; the list branch is purely defensive and skips bodies with no name to
// avoid producing a malformed "type." address.
func walkTypedBlocks(filePath string, doc model.Document, blockKey string, blockType BlockType) []Resource {
	typesMap, ok := toMap(doc[blockKey])
	if !ok {
		return nil
	}

	var resources []Resource
	for _, resourceType := range sortedKeys(typesMap) {
		switch named := typesMap[resourceType].(type) {
		case nil:
			continue
		default:
			if bodies, isList := toList(named); isList {
				for i, body := range bodies {
					// Use a 1-based index as a synthetic name so the address is
					// never empty (e.g. "aws_s3_bucket[0]").
					name := resourceType + "[" + itoa(i) + "]"
					resources = append(resources, newTerraformResource(filePath, blockType, resourceType, name, body))
				}
				continue
			}
			nameMap, isMap := toMap(named)
			if !isMap {
				continue
			}
			for _, name := range sortedKeys(nameMap) {
				resources = append(resources, newTerraformResource(filePath, blockType, resourceType, name, nameMap[name]))
			}
		}
	}
	return resources
}

func walkModuleBlocks(filePath string, doc model.Document) []Resource {
	moduleMap, ok := toMap(doc["module"])
	if !ok {
		return nil
	}

	var resources []Resource
	for _, name := range sortedKeys(moduleMap) {
		resources = append(resources, newTerraformResource(filePath, BlockModule, "", name, moduleMap[name]))
	}
	return resources
}

func newTerraformResource(filePath string, blockType BlockType, resourceType, name string, body interface{}) Resource {
	start := startLine(body)
	r := Resource{
		Platform:   platformTerraform,
		BlockType:  blockType,
		Type:       resourceType,
		Name:       name,
		Provider:   providerFromType(resourceType),
		File:       filePath,
		StartLine:  start,
		EndLine:    endLine(body, start),
		Attributes: attrsFromBody(body),
	}
	if blockType == BlockModule {
		r.ModuleSource = stringAttr(body, "source")
		r.ModuleVersion = stringAttr(body, "version")
	}
	return r
}

func providerFromType(resourceType string) string {
	if resourceType == "" {
		return ""
	}
	if idx := strings.Index(resourceType, "_"); idx > 0 {
		return resourceType[:idx]
	}
	return resourceType
}

// startLine reads the block's opening line from _dd_lines/_dd__default,
// tolerating both the struct and JSON-decoded forms.
func startLine(body interface{}) int {
	bodyMap, ok := toMap(body)
	if !ok {
		return 0
	}

	switch lines := bodyMap[ddLinesKey].(type) {
	case map[string]model.LineObject:
		return lines[ddDefaultKey].Line
	case map[string]*model.LineObject:
		if def := lines[ddDefaultKey]; def != nil {
			return def.Line
		}
	case map[string]interface{}:
		return lineFromGeneric(lines[ddDefaultKey])
	}
	return 0
}

// endLine returns the last annotated line inside the block (>= start). The
// Terraform converter does not record closing braces, so this is best-effort.
func endLine(body interface{}, start int) int {
	_, maxLine := lineBounds(body)
	if maxLine < start {
		return start
	}
	return maxLine
}

func lineFromGeneric(def interface{}) int {
	switch d := def.(type) {
	case model.LineObject:
		return d.Line
	case *model.LineObject:
		if d != nil {
			return d.Line
		}
	case map[string]interface{}:
		if line, ok := genericLine(d); ok {
			return line
		}
	}
	return 0
}
