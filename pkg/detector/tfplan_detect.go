/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/registry"
)

// TFPlanDetectLine is a detector for Terraform Plan files that maps findings back to HCL source
type TFPlanDetectLine struct {
	registry        *registry.AddressRegistry
	defaultDetector defaultDetectLine
}

// NewTFPlanDetectLine creates a new TFPlanDetectLine with the given registry
func NewTFPlanDetectLine(reg *registry.AddressRegistry) *TFPlanDetectLine {
	return &TFPlanDetectLine{
		registry:        reg,
		defaultDetector: defaultDetectLine{},
	}
}

// DetectLine searches for vulnerabilities in tfplan files by mapping addresses back to HCL source
func (t *TFPlanDetectLine) DetectLine(ctx context.Context, file *model.FileMetadata, searchKey string, outputLines int) model.VulnerabilityLines {
	contextLogger := logger.FromContext(ctx)

	// Registry is required - if nil, this is a programming error
	if t.registry == nil {
		contextLogger.Error().Msg("TFPlan detector created without registry - this is a bug")
		return t.defaultDetector.DetectLine(ctx, file, searchKey, outputLines)
	}

	// Extract the terraform address from the document
	address := extractAddressFromDocument(ctx, file, searchKey)
	if address == "" {
		// If we can't extract an address, fall back to default detection
		contextLogger.Debug().
			Str("searchKey", searchKey).
			Str("file", file.FilePath).
			Msg("TFPlan: Could not extract _dd_tf_address from document, falling back to default detection")
		return t.defaultDetector.DetectLine(ctx, file, searchKey, outputLines)
	}

	contextLogger.Info().
		Str("address", address).
		Str("searchKey", searchKey).
		Str("tfplanFile", file.FilePath).
		Msg("TFPlan: Extracted terraform address from document")

	// Multi-level detection strategy:
	// 1. Try to find the exact resource address (for root resources)
	// 2. Try to find the module call (for module resources)
	// 3. Fall back to default detection

	// First, try the full address (for root resources)
	// Use LookupWithScope to handle duplicates via scope-based disambiguation
	if location, found := t.registry.LookupWithScope(address, file.FilePath); found {
		contextLogger.Info().
			Str("address", address).
			Str("hclFile", location.FilePath).
			Int("line", location.Line).
			Str("tfplanFile", file.FilePath).
			Msg("TFPlan: Found exact address match in registry")
		return buildVulnerabilityLinesFromLocation(location, outputLines)
	}

	contextLogger.Info().
		Str("address", address).
		Int("registrySize", t.registry.GetMappingCount()).
		Msg("TFPlan: Exact address not found in registry, trying module extraction")

	// For module resources, try to find the module call
	moduleAddress := registry.ExtractModuleAddress(address)
	if moduleAddress != "" {
		contextLogger.Info().
			Str("fullAddress", address).
			Str("moduleAddress", moduleAddress).
			Msg("TFPlan: Extracted module address")

		// Use LookupWithScope to handle duplicate module addresses
		if location, found := t.registry.LookupWithScope(moduleAddress, file.FilePath); found {
			contextLogger.Info().
				Str("address", address).
				Str("moduleAddress", moduleAddress).
				Str("hclFile", location.FilePath).
				Int("line", location.Line).
				Str("tfplanFile", file.FilePath).
				Msg("TFPlan: Found module call match in registry")

			// TODO: In the future, we could try to look inside the module source
			// to find the specific attribute. For now, we point to the module call.
			return buildVulnerabilityLinesFromLocation(location, outputLines)
		}

		// Nested module not found, try parent modules iteratively
		// Example: "module.vpc.module.subnet" → "module.vpc"
		contextLogger.Info().
			Str("moduleAddress", moduleAddress).
			Msg("TFPlan: Full nested module not found, trying parent modules")

		parts := strings.Split(moduleAddress, ".")
		for len(parts) >= 2 {
			// Look for the last "module" keyword
			if len(parts) >= 2 && parts[len(parts)-2] == "module" {
				// Remove the last module.name pair
				parts = parts[:len(parts)-2]
				if len(parts) == 0 {
					break
				}
				parentModule := strings.Join(parts, ".")

				contextLogger.Info().
					Str("parentModule", parentModule).
					Msg("TFPlan: Trying parent module")

				// Use LookupWithScope to handle duplicate parent modules
				if location, found := t.registry.LookupWithScope(parentModule, file.FilePath); found {
					contextLogger.Info().
						Str("address", address).
						Str("parentModule", parentModule).
						Str("hclFile", location.FilePath).
						Int("line", location.Line).
						Str("tfplanFile", file.FilePath).
						Msg("TFPlan: Found parent module call match in registry")
					return buildVulnerabilityLinesFromLocation(location, outputLines)
				}
			} else {
				break
			}
		}

		contextLogger.Warn().
			Str("moduleAddress", moduleAddress).
			Msg("TFPlan: No module address found in registry (including parents)")
	}

	// If no mapping found, fall back to default detection
	contextLogger.Warn().
		Str("address", address).
		Str("moduleAddress", moduleAddress).
		Int("registrySize", t.registry.GetMappingCount()).
		Str("tfplanFile", file.FilePath).
		Msg("TFPlan: No address mapping found, falling back to default detection")
	return t.defaultDetector.DetectLine(ctx, file, searchKey, outputLines)
}

// extractAddressFromDocument extracts the _dd_tf_address field from the document
// by navigating the searchKey path to find the resource
// SearchKey formats:
//   - "aws_instance.web.ami" -> type: "aws_instance", key: "web"
//   - "aws_eip[module.vpc.nat[0]]" -> type: "aws_eip", key: "module.vpc.nat[0]"
//   - "resource.aws_s3_bucket.data.acl" -> type: "aws_s3_bucket", key: "data"
func extractAddressFromDocument(ctx context.Context, file *model.FileMetadata, searchKey string) string {
	contextLogger := logger.FromContext(ctx)

	// Strip "resource." prefix if present
	workingKey := searchKey
	if strings.HasPrefix(workingKey, "resource.") {
		workingKey = strings.TrimPrefix(workingKey, "resource.")
	}

	var resourceType, resourceKey string

	// Check if we have bracket notation: type[key].attribute.nested[0]
	bracketIdx := strings.Index(workingKey, "[")
	if bracketIdx > 0 {
		// Bracket notation: extract type and key from type[key]
		resourceType = workingKey[:bracketIdx]

		// Find the matching closing bracket for the first opening bracket
		// This handles cases like: aws_iam_policy_document[example].statement[0].actions[0]
		// We want to extract only "example", not "example].statement[0].actions[0"
		depth := 0
		closeBracketIdx := -1
		for i := bracketIdx; i < len(workingKey); i++ {
			if workingKey[i] == '[' {
				depth++
			} else if workingKey[i] == ']' {
				depth--
				if depth == 0 {
					closeBracketIdx = i
					break
				}
			}
		}

		if closeBracketIdx <= bracketIdx {
			contextLogger.Debug().
				Str("searchKey", searchKey).
				Msg("Invalid bracket notation: no matching closing bracket")
			return ""
		}

		// Extract the key between brackets
		resourceKey = workingKey[bracketIdx+1 : closeBracketIdx]

		contextLogger.Debug().
			Str("searchKey", searchKey).
			Str("resourceType", resourceType).
			Str("resourceKey", resourceKey).
			Msg("Parsed bracket notation searchKey")
	} else {
		// Dot notation: type.name.attribute
		parts := strings.Split(workingKey, ".")
		if len(parts) < 2 {
			contextLogger.Debug().
				Str("searchKey", searchKey).
				Int("parts", len(parts)).
				Msg("searchKey too short to extract type and key")
			return ""
		}

		// First part is type, second part is key
		resourceType = parts[0]
		resourceKey = parts[1]

		contextLogger.Debug().
			Str("searchKey", searchKey).
			Str("resourceType", resourceType).
			Str("resourceKey", resourceKey).
			Msg("Parsed dot notation searchKey")
	}

	// Navigate to resource section in LineInfoDocument (not Document)
	// LineInfoDocument contains _dd_tf_address and _dd_lines before stripping
	// Note: After JSON round-trip in parseTFPlan, nested objects are map[string]interface{}
	resourceSection, ok := file.LineInfoDocument["resource"]
	if !ok {
		contextLogger.Debug().Msg("No 'resource' section in LineInfoDocument")
		return ""
	}

	resourceMap, ok := resourceSection.(map[string]interface{})
	if !ok {
		contextLogger.Debug().
			Str("actualType", fmt.Sprintf("%T", resourceSection)).
			Msg("resource section is not a map[string]interface{}")
		return ""
	}

	// Navigate to resource type
	typeSection, ok := resourceMap[resourceType]
	if !ok {
		contextLogger.Debug().
			Str("resourceType", resourceType).
			Msg("Resource type not found in document")
		return ""
	}

	typeMap, ok := typeSection.(map[string]interface{})
	if !ok {
		contextLogger.Debug().
			Str("actualType", fmt.Sprintf("%T", typeSection)).
			Msg("type section is not a map[string]interface{}")
		return ""
	}

	// Navigate to resource key
	resourceAttrs, ok := typeMap[resourceKey]
	if !ok {
		contextLogger.Debug().
			Str("resourceType", resourceType).
			Str("resourceKey", resourceKey).
			Msg("Resource key not found in type map")
		return ""
	}

	attrsMap, ok := resourceAttrs.(map[string]interface{})
	if !ok {
		contextLogger.Debug().
			Str("actualType", fmt.Sprintf("%T", resourceAttrs)).
			Msg("resource attrs is not a map[string]interface{}")
		return ""
	}

	// Extract _dd_tf_address
	address, ok := attrsMap["_dd_tf_address"]
	if !ok {
		contextLogger.Debug().
			Str("resourceType", resourceType).
			Str("resourceKey", resourceKey).
			Msg("_dd_tf_address not found in resource attributes")
		return ""
	}

	addressStr, ok := address.(string)
	if !ok {
		contextLogger.Debug().Msg("_dd_tf_address is not a string")
		return ""
	}

	contextLogger.Info().
		Str("searchKey", searchKey).
		Str("resourceType", resourceType).
		Str("resourceKey", resourceKey).
		Str("extractedAddress", addressStr).
		Msg("Successfully extracted address from document")

	return addressStr
}

// extractResourceAddress extracts the Terraform resource address from a searchKey (DEPRECATED)
// This function is no longer used but kept for reference
// Examples:
//   - "resource.aws_instance.web.ami" -> "aws_instance.web"
//   - "resource.module.vpc.aws_vpc.main.cidr_block" -> "module.vpc.aws_vpc.main"
//   - "aws_instance.web[0].ami" -> "aws_instance.web"
func extractResourceAddress(searchKey string) string {
	// First, normalize the searchKey by removing any indices
	normalized := NormalizeTFPlanAddress(searchKey)

	// Handle different searchKey formats
	parts := strings.Split(normalized, ".")

	// Skip leading "resource" if present
	startIdx := 0
	if len(parts) > 0 && parts[0] == "resource" {
		startIdx = 1
	}

	// Build the address from the remaining parts
	// Stop before attribute names (usually the last part or two)
	var addressParts []string
	for i := startIdx; i < len(parts); i++ {
		part := parts[i]

		// Check if this looks like a resource type or name
		if i < len(parts)-1 {
			// Add module prefixes and resource types/names
			if part == "module" || (i > 0 && parts[i-1] == "module") {
				addressParts = append(addressParts, part)
			} else if i == startIdx || i == startIdx+1 {
				// First two parts after "resource" are type and name
				addressParts = append(addressParts, part)
			} else if len(addressParts) > 0 && strings.HasPrefix(addressParts[0], "module") {
				// This is part of a module path or a resource within a module
				addressParts = append(addressParts, part)
				// Stop after we have module.name.type.name pattern
				if len(addressParts) >= 4 && addressParts[len(addressParts)-3] != "module" {
					break
				}
			}
		}
	}

	if len(addressParts) < 2 {
		// Need at least type.name for a valid address
		return ""
	}

	return strings.Join(addressParts, ".")
}

// buildVulnerabilityLinesFromLocation creates VulnerabilityLines from a registry Location
func buildVulnerabilityLinesFromLocation(location registry.Location, outputLines int) model.VulnerabilityLines {
	// Read the file content to get the actual lines
	var lines []string
	if content, err := os.ReadFile(location.FilePath); err == nil {
		lines = strings.Split(string(content), "\n")
	}

	// Build the vulnerability lines using the existing helper
	// outputLines represents lines on each side, so total lines = outputLines*2 + 1
	totalLines := outputLines*2 + 1
	vulnLines := GetAdjacentVulnLines(location.Line-1, totalLines, lines)

	// Create the location information
	startLine := model.ResourceLine{
		Line: location.Line,
		Col:  location.Column,
	}

	// For end location, try to find the end of the resource block
	endLine := startLine
	if len(lines) > location.Line-1 {
		// Simple heuristic: set column to end of the line
		// This is a simplified approach - a more robust solution would parse the HCL
		endLine.Line = location.Line
		endLine.Col = len(lines[location.Line-1])
	}

	return model.VulnerabilityLines{
		Line:         location.Line,
		VulnLines:    vulnLines,
		ResolvedFile: location.FilePath,
		VulnerablilityLocation: model.ResourceLocation{
			Start: startLine,
			End:   endLine,
		},
		ResourceSource: location.FilePath,
		FileSource:     []string{location.FilePath},
	}
}

// NormalizeTFPlanAddress removes all count/for_each indices from a tfplan address
// This is used to match tfplan addresses with HCL-registered addresses
func NormalizeTFPlanAddress(address string) string {
	return registry.NormalizeAddress(address)
}
