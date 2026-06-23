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

// ParseSearchKey parses a Terraform search key into its structured components
//
// Supported formats:
//   - Simple resource: "aws_instance.web.tags"
//   - Resource prefix: "resource.aws_instance.web.tags"
//   - Bracket notation: "aws_instance[web].tags"
//   - Module resource: "module.vpc.aws_instance.bastion.tags"
//   - Indexed module: "module.app_servers[0].aws_instance.app.tags"
//   - Mixed notation: "aws_instance.module.app_servers[0].app" (module in middle)
//   - Bracket with module: "aws_instance[module.app_servers[0].app]"
//   - Template syntax: "aws_instance.{{module.app_servers[0].app}}"
//
// Returns error for invalid formats (empty, single component, mismatched brackets)
func ParseSearchKey(searchKey string) (*ParsedSearchKey, error) {
	if searchKey == "" {
		return nil, fmt.Errorf("searchKey is empty")
	}

	// Step 1: Preprocess - strip "resource." prefix
	workingKey := searchKey
	if strings.HasPrefix(workingKey, "resource.") {
		workingKey = strings.TrimPrefix(workingKey, "resource.")
	}

	// Step 2: Handle template syntax {{...}}
	// Handles both "{{module.app.resource}}" and "type.{{module.app.resource}}"
	if strings.Contains(workingKey, "{{") {
		openBrace := strings.Index(workingKey, "{{")
		closeBrace := strings.Index(workingKey, "}}")

		// Validate template syntax
		if closeBrace == -1 || closeBrace <= openBrace+2 {
			return nil, fmt.Errorf("unmatched template braces in searchKey: %s", searchKey)
		}

		// Extract template content
		templateContent := workingKey[openBrace+2 : closeBrace]

		// Check if there's a prefix before the template
		if openBrace > 0 {
			// Format: type.{{module.app.resource}}
			// Combine prefix + template content
			prefix := workingKey[:openBrace]
			if strings.HasSuffix(prefix, ".") {
				prefix = prefix[:len(prefix)-1]
			}
			workingKey = prefix + "." + templateContent
		} else {
			// Format: {{module.app.resource}}
			workingKey = templateContent
		}
	}

	// Step 3: Determine the format and parse accordingly

	// Check for module path FIRST (starts with "module.")
	// This must come before bracket notation check to handle module.name[index].resource correctly
	if strings.HasPrefix(workingKey, "module.") {
		return parseModulePath(workingKey, searchKey)
	}

	// Check for bracket notation and mixed notation
	bracketIdx := strings.Index(workingKey, "[")
	moduleIdx := strings.Index(workingKey, ".module.")

	// Determine if this is mixed notation or bracket notation:
	// - Mixed notation: type.module.path.resource (brackets come AFTER .module.)
	// - Bracket notation: type[module.path.resource] (brackets come BEFORE .module. or no .module.)

	// Check for mixed notation: type.module.path.resource
	// This handles: aws_instance.module.app_servers[0].app
	if moduleIdx != -1 && (bracketIdx == -1 || moduleIdx < bracketIdx) {
		return parseMixedNotation(workingKey, searchKey)
	}

	// Check for bracket notation if brackets exist
	// This handles: aws_subnet[module.network.module.subnet.private]
	if bracketIdx > 0 {
		return parseBracketNotation(workingKey, bracketIdx, searchKey)
	}

	// Simple dot notation: type.name[.attributes...]
	return parseSimpleDotNotation(workingKey, searchKey)
}

// parseBracketNotation handles formats like:
//   - aws_instance[web].tags
//   - aws_instance[module.app_servers[0].app]
//   - aws_instance[module.app_servers[0].app].tags
func parseBracketNotation(workingKey string, bracketIdx int, originalKey string) (*ParsedSearchKey, error) {
	resourceType := workingKey[:bracketIdx]

	// Find matching closing bracket
	closeBracketIdx := findMatchingBracket(workingKey, bracketIdx)
	if closeBracketIdx == -1 {
		return nil, fmt.Errorf("unmatched opening bracket in searchKey: %s", originalKey)
	}

	bracketContent := workingKey[bracketIdx+1 : closeBracketIdx]

	// Check if bracket content is a module path
	// Format: aws_instance[module.app_servers[0].app]
	// where resourceType = "aws_instance", bracketContent = "module.app_servers[0].app"
	if strings.HasPrefix(bracketContent, "module.") || strings.Contains(bracketContent, ".module.") {
		// Parse the bracket content to extract module path and resource name
		// Split the bracket content by dots, preserving indices
		parts := splitPreservingBrackets(bracketContent)

		// Extract module path components
		var modulePath []string
		i := 0

		// Parse modules: module.name[index]...
		for i < len(parts)-1 { // -1 because last part is resource name
			if parts[i] == "module" {
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
				// Not a module keyword, must be resource name
				break
			}
		}

		if i >= len(parts) {
			return nil, fmt.Errorf("no resource name found in bracket module path: %s", originalKey)
		}

		// Last part is resource name
		resourceNameWithIndex := parts[i]
		resourceName, _ := extractNameAndIndex(resourceNameWithIndex)

		// Extract any attributes after the bracket
		remainder := ""
		if closeBracketIdx+1 < len(workingKey) {
			remainder = workingKey[closeBracketIdx+1:]
			if strings.HasPrefix(remainder, ".") {
				remainder = remainder[1:]
			}
		}

		var attributePath []string
		if remainder != "" {
			attributePath = strings.Split(remainder, ".")
		}

		// Build full address
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

	// Simple bracket notation: aws_instance[web].tags or aws_instance["example"].tags
	// Remove any indices and quotes from the resource name
	resourceName := registry.NormalizeAddress(bracketContent)
	// Strip surrounding quotes if present (for string keys like ["example"])
	resourceName = strings.Trim(resourceName, `"'`)

	// Extract attributes after bracket
	var attributePath []string
	remainder := ""
	if closeBracketIdx+1 < len(workingKey) {
		remainder = workingKey[closeBracketIdx+1:]
		if strings.HasPrefix(remainder, ".") {
			remainder = remainder[1:]
		}
	}

	if remainder != "" {
		attributePath = strings.Split(remainder, ".")
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

// parseModulePath handles formats like:
//   - module.vpc.aws_instance.bastion.tags
//   - module.app_servers[0].aws_instance.app.tags
//   - module.network.module.subnet.aws_subnet.private.cidr_block
func parseModulePath(workingKey string, originalKey string) (*ParsedSearchKey, error) {
	// Parse module path and find where the resource starts
	parts := splitPreservingBrackets(workingKey)

	if len(parts) < 4 {
		// Need at least: module, name, type, resource_name
		return nil, fmt.Errorf("module path too short: %s", originalKey)
	}

	// Extract module path components
	var modulePath []string
	i := 0

	// Parse nested modules: module.name.module.name...
	for i < len(parts)-2 {
		if parts[i] == "module" {
			// Add "module"
			modulePath = append(modulePath, parts[i])
			i++

			// Next part is the module name (might have index)
			if i < len(parts) {
				nameWithIndex := parts[i]
				// Extract base name and any index
				baseName, index := extractNameAndIndex(nameWithIndex)
				modulePath = append(modulePath, baseName)
				if index != "" {
					modulePath = append(modulePath, index)
				}
				i++
			}
		} else {
			// Not a module keyword, must be resource type
			break
		}
	}

	if i >= len(parts)-1 {
		// No resource type/name found
		return nil, fmt.Errorf("no resource type found in module path: %s", originalKey)
	}

	// Next part is resource type
	resourceType := parts[i]
	i++

	// Next part is resource name
	if i >= len(parts) {
		return nil, fmt.Errorf("no resource name found: %s", originalKey)
	}

	resourceNameWithIndex := parts[i]
	resourceName, _ := extractNameAndIndex(resourceNameWithIndex)
	i++

	// Remaining parts are attributes
	var attributePath []string
	if i < len(parts) {
		attributePath = parts[i:]
	}

	// Build full address with indices
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

// parseMixedNotation handles the problematic format:
//   - aws_instance.module.app_servers[0].app
//
// Where "module" appears after the resource type
// Format: type.module.module_name[index].resource_name[.attributes...]
func parseMixedNotation(workingKey string, originalKey string) (*ParsedSearchKey, error) {
	// Use splitPreservingBrackets to handle indices correctly
	parts := splitPreservingBrackets(workingKey)

	if len(parts) < 4 {
		// Need: type, module, module_name, resource_name
		return nil, fmt.Errorf("mixed notation too short: %s (need at least type.module.name.resource)", originalKey)
	}

	// First part is resource type
	resourceType := parts[0]

	// Find where "module" appears
	moduleIdx := -1
	for i, part := range parts {
		if part == "module" {
			moduleIdx = i
			break
		}
	}

	if moduleIdx == -1 {
		return nil, fmt.Errorf("module keyword not found in mixed notation: %s", originalKey)
	}

	// Parse module path: from "module" keyword until the last part (which is resource name or first attribute)
	// Format: module.name[index]....resource_name
	var modulePath []string
	i := moduleIdx

	// Parse nested modules
	for i < len(parts)-1 { // -1 because last part might be resource name
		if parts[i] == "module" {
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
			// Not "module" keyword, must be resource name or attribute
			break
		}
	}

	// Remaining parts: first is resource name, rest are attributes
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

	// Build full address
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
func parseSimpleDotNotation(workingKey string, originalKey string) (*ParsedSearchKey, error) {
	// Validate no unmatched brackets
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

// findMatchingBracket finds the closing bracket matching the opening bracket at startIdx
func findMatchingBracket(s string, startIdx int) int {
	depth := 0
	for i := startIdx; i < len(s); i++ {
		if s[i] == '[' {
			depth++
		} else if s[i] == ']' {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// splitPreservingBrackets splits a string by dots, but keeps bracket contents together
// Example: "module.app[0].aws_instance.web" → ["module", "app[0]", "aws_instance", "web"]
func splitPreservingBrackets(s string) []string {
	var parts []string
	var current strings.Builder
	inBracket := false

	for _, ch := range s {
		if ch == '[' {
			inBracket = true
			current.WriteRune(ch)
		} else if ch == ']' {
			inBracket = false
			current.WriteRune(ch)
		} else if ch == '.' && !inBracket {
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		} else {
			current.WriteRune(ch)
		}
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}

// extractNameAndIndex separates a name with optional index
// Examples:
//   - "app[0]" → ("app", "0")
//   - "web" → ("web", "")
//   - "vpc[\"prod\"]" → ("vpc", "prod")
func extractNameAndIndex(nameWithIndex string) (string, string) {
	bracketIdx := strings.Index(nameWithIndex, "[")
	if bracketIdx == -1 {
		return nameWithIndex, ""
	}

	name := nameWithIndex[:bracketIdx]
	closeBracketIdx := findMatchingBracket(nameWithIndex, bracketIdx)
	if closeBracketIdx == -1 {
		return nameWithIndex, ""
	}

	index := nameWithIndex[bracketIdx+1 : closeBracketIdx]
	// Remove quotes if present
	index = strings.Trim(index, `"'`)

	return name, index
}

// buildFullAddress constructs the full Terraform address from components
// Examples:
//   - modulePath=["module", "vpc"], type="aws_instance", name="web" → "module.vpc.aws_instance.web"
//   - modulePath=["module", "app", "0"], type="aws_instance", name="web[1]" → "module.app[0].aws_instance.web[1]"
func buildFullAddress(modulePath []string, resourceType, resourceName string) string {
	var parts []string

	// Add module path with proper indexing
	for i := 0; i < len(modulePath); i++ {
		if modulePath[i] == "module" {
			// Add "module"
			if i+1 < len(modulePath) {
				moduleName := modulePath[i+1]

				// Check if next element is an index
				if i+2 < len(modulePath) && modulePath[i+2] != "module" {
					// It's an index
					index := modulePath[i+2]
					parts = append(parts, fmt.Sprintf("module.%s[%s]", moduleName, index))
					i += 2 // Skip name and index
				} else {
					// No index
					parts = append(parts, fmt.Sprintf("module.%s", moduleName))
					i++ // Skip name
				}
			}
		}
	}

	// Add resource type and name
	resourcePart := fmt.Sprintf("%s.%s", resourceType, resourceName)
	parts = append(parts, resourcePart)

	return strings.Join(parts, ".")
}
