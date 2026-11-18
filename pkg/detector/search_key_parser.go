/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"fmt"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/registry"
)

// minModulePathParts is the minimum component count for a module search key:
// module, name, resource type, resource name.
const minModulePathParts = 4

// moduleKeyword is the "module" path segment in a dotted Terraform address.
const moduleKeyword = "module"

// ParsedSearchKey represents the structured result of parsing a Terraform search key
// This provides all the information needed to properly map TFPlan findings to HCL source
type ParsedSearchKey struct {
	// Resource identification
	ResourceType string   // e.g., "aws_instance"
	ResourceName string   // e.g., "web" or "app" (just the name, not the full path)
	ModulePath   []string // e.g., ["module", "app_servers", "0"] for module.app_servers[0]

	// Address components
	FullResourceAddr string // e.g., "module.app_servers[0].aws_instance.web"
	NormalizedAddr   string // e.g., "module.app_servers.aws_instance.web" (indices removed)

	// Attribute path (if attribute-level finding)
	AttributePath []string // e.g., ["tags", "Name"] for multi-level attributes

	// Finding level classification
	HasAttribute     bool // true if this finding targets a specific attribute
	IsResourceLevel  bool // true if no attribute, just resource block
	IsModuleResource bool // true if resource is within a module
}

// ParseSearchKey parses a Terraform search key into its structured components.
// Returns error for invalid formats (empty, single component, mismatched brackets).
func ParseSearchKey(searchKey string) (*ParsedSearchKey, error) {
	if searchKey == "" {
		return nil, fmt.Errorf("searchKey is empty")
	}

	workingKey := strings.TrimPrefix(searchKey, "resource.")

	// Handle template syntax {{...}}. Unwrap the braces in place, keeping
	// both the prefix before "{{" and the suffix after "}}" intact, so bracket
	// notation like "aws_s3_bucket_object[{{this[0]}}]" or an attribute suffix
	// like "{{module.app.resource}}.tags" survive unwrapping unchanged.
	if strings.Contains(workingKey, "{{") {
		openBrace := strings.Index(workingKey, "{{")
		closeBrace := strings.Index(workingKey, "}}")

		if closeBrace == -1 || closeBrace <= openBrace+2 {
			return nil, fmt.Errorf("unmatched template braces in searchKey: %s", searchKey)
		}

		prefix := workingKey[:openBrace]
		templateContent := workingKey[openBrace+2 : closeBrace]
		suffix := workingKey[closeBrace+2:]

		// A dot-notation prefix like "type." needs its own trailing dot merged
		// with the template content; bracket notation like "type[" doesn't.
		if strings.HasSuffix(prefix, ".") {
			prefix = strings.TrimSuffix(prefix, ".")
			workingKey = prefix + "." + templateContent + suffix
		} else {
			workingKey = prefix + templateContent + suffix
		}
	}

	// Module path check must come before bracket notation to handle
	// module.name[index].resource correctly.
	if strings.HasPrefix(workingKey, "module.") {
		return parseModulePath(workingKey, searchKey)
	}

	bracketIdx := strings.Index(workingKey, "[")
	moduleIdx := strings.Index(workingKey, ".module.")

	// Mixed notation (type.module.path.resource) has brackets after ".module.";
	// bracket notation (type[module.path.resource]) has them before, or no ".module." at all.
	if moduleIdx != -1 && (bracketIdx == -1 || moduleIdx < bracketIdx) {
		return parseMixedNotation(workingKey, searchKey)
	}

	if bracketIdx > 0 {
		return parseBracketNotation(workingKey, bracketIdx, searchKey)
	}

	return parseSimpleDotNotation(workingKey, searchKey)
}

// parseBracketNotation handles formats like:
//   - aws_instance[web].tags
//   - aws_instance[module.app_servers[0].app]
//   - aws_instance[module.app_servers[0].app].tags
func parseBracketNotation(workingKey string, bracketIdx int, originalKey string) (*ParsedSearchKey, error) {
	resourceType := workingKey[:bracketIdx]

	closeBracketIdx := findMatchingBracketSimple(workingKey, bracketIdx)
	if closeBracketIdx == -1 {
		return nil, fmt.Errorf("unmatched opening bracket in searchKey: %s", originalKey)
	}

	bracketContent := workingKey[bracketIdx+1 : closeBracketIdx]

	// e.g. aws_instance[module.app_servers[0].app]: resourceType="aws_instance",
	// bracketContent="module.app_servers[0].app"
	if strings.HasPrefix(bracketContent, "module.") || strings.Contains(bracketContent, ".module.") {
		parts := splitPreservingBrackets(bracketContent)

		var modulePath []string
		i := 0

		for i < len(parts)-1 { // -1 because last part is resource name
			if parts[i] == moduleKeyword {
				modulePath = append(modulePath, parts[i])
				i++
				if i < len(parts) {
					nameWithIndex := parts[i]
					baseName, index := extractNameAndIndex(nameWithIndex)
					modulePath = append(modulePath, baseName)
					if index != "" {
						modulePath = append(modulePath, index)
					}
					i++
				}
			} else {
				break
			}
		}

		if i >= len(parts) {
			return nil, fmt.Errorf("no resource name found in bracket module path: %s", originalKey)
		}

		resourceNameWithIndex := parts[i]
		resourceName, _ := extractNameAndIndex(resourceNameWithIndex)

		remainder := ""
		if closeBracketIdx+1 < len(workingKey) {
			remainder = strings.TrimPrefix(workingKey[closeBracketIdx+1:], ".")
		}

		var attributePath []string
		if remainder != "" {
			attributePath = strings.Split(remainder, ".")
		}

		fullAddr := buildFullAddress(modulePath, resourceType, resourceNameWithIndex)
		normalizedAddr := registry.NormalizeAddress(fullAddr)

		return &ParsedSearchKey{
			ResourceType:     resourceType,
			ResourceName:     resourceName,
			ModulePath:       modulePath,
			FullResourceAddr: fullAddr,
			NormalizedAddr:   normalizedAddr,
			AttributePath:    attributePath,
			HasAttribute:     len(attributePath) > 0,
			IsResourceLevel:  len(attributePath) == 0,
			IsModuleResource: true,
		}, nil
	}

	// bracketContent may itself carry a count/for_each index (e.g. "this[0]", a
	// module resource's instance key) - keep it as-is (indices and quotes) in
	// FullResourceAddr, matching parseModulePath's convention, and only strip it
	// for the normalized address.
	resourceName := strings.Trim(registry.NormalizeAddress(bracketContent), `"'`)

	var attributePath []string
	remainder := ""
	if closeBracketIdx+1 < len(workingKey) {
		remainder = strings.TrimPrefix(workingKey[closeBracketIdx+1:], ".")
	}

	if remainder != "" {
		attributePath = strings.Split(remainder, ".")
	}

	return &ParsedSearchKey{
		ResourceType:     resourceType,
		ResourceName:     resourceName,
		ModulePath:       nil,
		FullResourceAddr: fmt.Sprintf("%s.%s", resourceType, bracketContent),
		NormalizedAddr:   fmt.Sprintf("%s.%s", resourceType, resourceName),
		AttributePath:    attributePath,
		HasAttribute:     len(attributePath) > 0,
		IsResourceLevel:  len(attributePath) == 0,
		IsModuleResource: false,
	}, nil
}

// parseModulePath handles formats like:
//   - module.vpc.aws_instance.bastion.tags
//   - module.app_servers[0].aws_instance.app.tags
//   - module.network.module.subnet.aws_subnet.private.cidr_block
func parseModulePath(workingKey, originalKey string) (*ParsedSearchKey, error) {
	parts := splitPreservingBrackets(workingKey)

	if len(parts) < minModulePathParts {
		// Need at least: module, name, type, resource_name
		return nil, fmt.Errorf("module path too short: %s", originalKey)
	}

	var modulePath []string
	i := 0

	// Parse nested modules: module.name.module.name...
	for i < len(parts)-2 {
		if parts[i] == moduleKeyword {
			modulePath = append(modulePath, parts[i])
			i++

			if i < len(parts) {
				nameWithIndex := parts[i]
				baseName, index := extractNameAndIndex(nameWithIndex)
				modulePath = append(modulePath, baseName)
				if index != "" {
					modulePath = append(modulePath, index)
				}
				i++
			}
		} else {
			break
		}
	}

	if i >= len(parts)-1 {
		return nil, fmt.Errorf("no resource type found in module path: %s", originalKey)
	}

	resourceType := parts[i]
	i++

	if i >= len(parts) {
		return nil, fmt.Errorf("no resource name found: %s", originalKey)
	}

	resourceNameWithIndex := parts[i]
	resourceName, _ := extractNameAndIndex(resourceNameWithIndex)
	i++

	var attributePath []string
	if i < len(parts) {
		attributePath = parts[i:]
	}

	fullAddr := buildFullAddress(modulePath, resourceType, resourceNameWithIndex)
	normalizedAddr := registry.NormalizeAddress(fullAddr)

	return &ParsedSearchKey{
		ResourceType:     resourceType,
		ResourceName:     resourceName,
		ModulePath:       modulePath,
		FullResourceAddr: fullAddr,
		NormalizedAddr:   normalizedAddr,
		AttributePath:    attributePath,
		HasAttribute:     len(attributePath) > 0,
		IsResourceLevel:  len(attributePath) == 0,
		IsModuleResource: true,
	}, nil
}

// parseMixedNotation handles the format where "module" appears after the resource type:
//   - aws_instance.module.app_servers[0].app
//
// Format: type.module.module_name[index].resource_name[.attributes...]
func parseMixedNotation(workingKey, originalKey string) (*ParsedSearchKey, error) {
	parts := splitPreservingBrackets(workingKey)

	if len(parts) < minModulePathParts {
		// Need: type, module, module_name, resource_name
		return nil, fmt.Errorf("mixed notation too short: %s (need at least type.module.name.resource)", originalKey)
	}

	resourceType := parts[0]

	moduleIdx := -1
	for i, part := range parts {
		if part == moduleKeyword {
			moduleIdx = i
			break
		}
	}

	if moduleIdx == -1 {
		return nil, fmt.Errorf("module keyword not found in mixed notation: %s", originalKey)
	}

	var modulePath []string
	i := moduleIdx

	for i < len(parts)-1 { // -1 because last part might be resource name
		if parts[i] == moduleKeyword {
			modulePath = append(modulePath, parts[i])
			i++
			if i < len(parts) {
				nameWithIndex := parts[i]
				baseName, index := extractNameAndIndex(nameWithIndex)
				modulePath = append(modulePath, baseName)
				if index != "" {
					modulePath = append(modulePath, index)
				}
				i++
			}
		} else {
			break
		}
	}

	if i >= len(parts) {
		return nil, fmt.Errorf("no resource name found in mixed notation: %s", originalKey)
	}

	resourceNameWithIndex := parts[i]
	resourceName, _ := extractNameAndIndex(resourceNameWithIndex)
	i++

	var attributePath []string
	if i < len(parts) {
		attributePath = parts[i:]
	}

	fullAddr := buildFullAddress(modulePath, resourceType, resourceNameWithIndex)
	normalizedAddr := registry.NormalizeAddress(fullAddr)

	return &ParsedSearchKey{
		ResourceType:     resourceType,
		ResourceName:     resourceName,
		ModulePath:       modulePath,
		FullResourceAddr: fullAddr,
		NormalizedAddr:   normalizedAddr,
		AttributePath:    attributePath,
		HasAttribute:     len(attributePath) > 0,
		IsResourceLevel:  len(attributePath) == 0,
		IsModuleResource: true,
	}, nil
}

// parseSimpleDotNotation handles simple formats:
//   - aws_instance.web
//   - aws_instance.web.tags
//   - aws_instance.web.root_block_device.volume_size
func parseSimpleDotNotation(workingKey, originalKey string) (*ParsedSearchKey, error) {
	if strings.Contains(workingKey, "]") && !strings.Contains(workingKey, "[") {
		return nil, fmt.Errorf("unmatched closing bracket in searchKey: %s", originalKey)
	}

	parts := strings.Split(workingKey, ".")

	if len(parts) < 2 {
		return nil, fmt.Errorf("searchKey must have at least type and name: %s", originalKey)
	}

	resourceType := parts[0]
	resourceNameWithIndex := parts[1]
	resourceName, _ := extractNameAndIndex(resourceNameWithIndex)

	var attributePath []string
	if len(parts) > 2 {
		attributePath = parts[2:]
	}

	return &ParsedSearchKey{
		ResourceType:     resourceType,
		ResourceName:     resourceName,
		ModulePath:       nil,
		FullResourceAddr: fmt.Sprintf("%s.%s", resourceType, resourceName),
		NormalizedAddr:   fmt.Sprintf("%s.%s", resourceType, resourceName),
		AttributePath:    attributePath,
		HasAttribute:     len(attributePath) > 0,
		IsResourceLevel:  len(attributePath) == 0,
		IsModuleResource: false,
	}, nil
}

// Helper functions

// findMatchingBracketSimple finds the closing bracket matching the opening bracket at startIdx.
// Quote- and escape-aware, since a for_each string key can itself contain a literal "]" or "["
// (e.g. aws_instance.web[module.secrets["prod]eu"].name]).
func findMatchingBracketSimple(s string, startIdx int) int {
	depth := 0
	inQuotes := false
	for i := startIdx; i < len(s); i++ {
		switch {
		case s[i] == '\\' && inQuotes:
			i++ // skip the escaped character entirely
		case s[i] == '"':
			inQuotes = !inQuotes
		case s[i] == '[' && !inQuotes:
			depth++
		case s[i] == ']' && !inQuotes:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// splitPreservingBrackets splits a string by dots, but keeps bracket contents together.
// Quote- and escape-aware, since a for_each string key can itself contain a literal "]",
// "[", or "." (e.g. module.secrets["prod].eu"].aws_instance.web).
// Example: "module.app[0].aws_instance.web" → ["module", "app[0]", "aws_instance", "web"]
func splitPreservingBrackets(s string) []string {
	var parts []string
	var current strings.Builder
	depth := 0
	inQuotes := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '\\' && inQuotes:
			i = writeEscapedByte(&current, s, i)
		case ch == '"':
			inQuotes = !inQuotes
			current.WriteByte(ch)
		case ch == '[' && !inQuotes:
			depth++
			current.WriteByte(ch)
		case ch == ']' && !inQuotes:
			if depth > 0 {
				depth--
			}
			current.WriteByte(ch)
		case ch == '.' && depth == 0 && !inQuotes:
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(ch)
		}
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}

// writeEscapedByte writes the backslash at s[i] and the character it escapes (if any) to dst
// verbatim, returning the index of the last byte consumed.
func writeEscapedByte(dst *strings.Builder, s string, i int) int {
	dst.WriteByte(s[i])
	if i+1 < len(s) {
		i++
		dst.WriteByte(s[i])
	}
	return i
}

// extractNameAndIndex separates a name with optional index
// Examples:
//   - "app[0]" → ("app", "0")
//   - "web" → ("web", "")
//   - "vpc[\"prod\"]" → ("vpc", "prod")
func extractNameAndIndex(nameWithIndex string) (name, index string) {
	bracketIdx := strings.Index(nameWithIndex, "[")
	if bracketIdx == -1 {
		return nameWithIndex, ""
	}

	name = nameWithIndex[:bracketIdx]
	closeBracketIdx := findMatchingBracketSimple(nameWithIndex, bracketIdx)
	if closeBracketIdx == -1 {
		return nameWithIndex, ""
	}

	index = strings.Trim(nameWithIndex[bracketIdx+1:closeBracketIdx], `"'`)

	return name, index
}

// buildFullAddress constructs the full Terraform address from components
// Examples:
//   - modulePath=["module", "vpc"], type="aws_instance", name="web" → "module.vpc.aws_instance.web"
//   - modulePath=["module", "app", "0"], type="aws_instance", name="web[1]" → "module.app[0].aws_instance.web[1]"
func buildFullAddress(modulePath []string, resourceType, resourceName string) string {
	var parts []string

	for i := 0; i < len(modulePath); i++ {
		if modulePath[i] == moduleKeyword {
			if i+1 < len(modulePath) {
				moduleName := modulePath[i+1]

				if i+2 < len(modulePath) && modulePath[i+2] != moduleKeyword {
					index := modulePath[i+2]
					parts = append(parts, fmt.Sprintf("module.%s[%s]", moduleName, index))
					i += 2 // Skip name and index
				} else {
					parts = append(parts, fmt.Sprintf("module.%s", moduleName))
					i++ // Skip name
				}
			}
		}
	}

	resourcePart := fmt.Sprintf("%s.%s", resourceType, resourceName)
	parts = append(parts, resourcePart)

	return strings.Join(parts, ".")
}
