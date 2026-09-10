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
	"path/filepath"
	"regexp"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/registry"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/rs/zerolog"
)

// Origin hint values for a TFPlan attribute, as attached by tfplan.go's
// annotateOriginsFromConfig: where the offending value was actually set.
const (
	originModuleHardcoded = "module_hardcoded"
	originModuleDefault   = "module_default"
	originCall            = "call"
)

// TFPlanDetectLine is a detector for Terraform Plan files that maps findings back to HCL source
//
// ARCHITECTURE NOTE - Module Mapping Scope Limitations:
//
// The current implementation has a scope limitation with module mappings:
//
// 1. Module deduplication (pkg/parser/terraform/modules/modules.go:172):
//   - Modules are deduplicated by SOURCE at parse time
//   - Same source called multiple times = single module entry
//
// 2. Module mapping conversion (pkg/engine/inspector.go:502):
//   - Local modules: keyed by NAME only (not source)
//   - Remote modules: keyed by SOURCE::NAME
//
// 3. Impact:
//   - Can lose call-site identity when same source is called under different names
//   - Can lose call-site identity when same local module name appears in different scopes
//
// This is ACCEPTABLE for v1 because:
//   - The address registry (which handles resource location lookup) is scope-aware
//   - Most real-world scenarios don't hit this edge case
//   - The transformation logic has fallback paths that preserve resource identity
//
// Future enhancement:
//   - Make module mapping scope-aware to match address registry's approach
//   - Use call-site location + source as key instead of just source/name
type TFPlanDetectLine struct {
	registry        *registry.AddressRegistry
	moduleMappings  map[string]interface{}
	defaultDetector defaultDetectLine
}

// NewTFPlanDetectLine creates a new TFPlanDetectLine with the given registry and module mappings
func NewTFPlanDetectLine(reg *registry.AddressRegistry, modules map[string]interface{}) *TFPlanDetectLine {
	return &TFPlanDetectLine{
		registry:        reg,
		moduleMappings:  modules,
		defaultDetector: defaultDetectLine{},
	}
}

// resolveRootResourceLocation builds the finding for an exact root-resource address match.
//
// CRITICAL: Canonicalize the searchKey for similarity ID deduplication
// Root resources with count/for_each (e.g., aws_instance.web[0], aws_instance.web[1])
// must use the same normalized key to deduplicate to a single finding.
//
// COUNT CONTRACT FOR ATTRIBUTE-LEVEL FINDINGS:
//   - Attribute-level findings (e.g., "aws_instance.web[0].tags") are canonicalized
//     to "aws_instance.web.tags" for deduplication across count/for_each instances
//   - Result: N instances → 1 finding (pointing to HCL resource definition)
//
// COUNT CONTRACT FOR RESOURCE-LEVEL FINDINGS:
//   - Resource-level findings (e.g., "aws_instance.web[0]" with no attribute) currently
//     keep the full address including indices for similarity computation
//   - This is ACCEPTABLE because:
//     1. Most rules target specific attributes, not entire resources
//     2. Resource-level findings often represent different violations per instance
//     3. The HCL mapping still works correctly (all point to .tf files)
//   - Future enhancement: If resource-level deduplication is desired, apply the same
//     canonicalization by removing the index check below
func resolveRootResourceLocation(
	ctx context.Context, location registry.Location, searchKey string, outputLines int,
) model.VulnerabilityLines {
	contextLogger := logger.FromContext(ctx)

	// Parse the searchKey to extract the normalized address (indices stripped)
	parsed, err := ParseSearchKey(searchKey)
	if err != nil || parsed.NormalizedAddr == "" {
		// Fallback if parsing fails (shouldn't happen for valid searchKeys)
		return buildVulnerabilityLinesFromLocation(location, outputLines)
	}

	if !parsed.HasAttribute || len(parsed.AttributePath) == 0 {
		// Resource-level finding (no attribute)
		// Currently using full address to preserve per-instance findings
		// This is the documented behavior per COUNT CONTRACT above
		contextLogger.Debug().
			Str("searchKey", searchKey).
			Msg("TFPlan: Resource-level finding, using full address (no canonicalization)")
		return buildVulnerabilityLinesFromLocation(location, outputLines)
	}

	// Use the normalized address as the canonical key for similarity ID
	// This ensures aws_instance.web[0].tags and aws_instance.web[1].tags
	// both use "aws_instance.web.tags" for similarity computation
	canonicalKey := parsed.NormalizedAddr + "." + strings.Join(parsed.AttributePath, ".")

	contextLogger.Debug().
		Str("originalSearchKey", searchKey).
		Str("canonicalKey", canonicalKey).
		Msg("TFPlan: Using canonical searchKey for root resource deduplication")

	return buildVulnerabilityLinesFromLocation(location, outputLines, canonicalKey)
}

// DetectLine searches for vulnerabilities in tfplan files by mapping addresses back to HCL source
func (t *TFPlanDetectLine) DetectLine(
	ctx context.Context, file *model.FileMetadata, searchKey string, outputLines int,
) model.VulnerabilityLines {
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

	contextLogger.Debug().
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
		contextLogger.Debug().
			Str("address", address).
			Str("hclFile", location.FilePath).
			Int("line", location.Line).
			Str("tfplanFile", file.FilePath).
			Msg("TFPlan: Found exact address match in registry")

		return resolveRootResourceLocation(ctx, location, searchKey, outputLines)
	}

	contextLogger.Debug().
		Str("address", address).
		Int("registrySize", t.registry.GetMappingCount()).
		Msg("TFPlan: Exact address not found in registry, trying module extraction")

	// For module resources, try to find the module call
	moduleAddress := registry.ExtractModuleAddress(address)
	if moduleAddress != "" {
		contextLogger.Debug().
			Str("fullAddress", address).
			Str("moduleAddress", moduleAddress).
			Msg("TFPlan: Extracted module address")

		// Use LookupWithScope to handle duplicate module addresses
		if location, found := t.registry.LookupWithScope(moduleAddress, file.FilePath); found {
			contextLogger.Debug().
				Str("address", address).
				Str("moduleAddress", moduleAddress).
				Str("hclFile", location.FilePath).
				Int("line", location.Line).
				Str("tfplanFile", file.FilePath).
				Msg("TFPlan: Found module call match in registry")

			return t.resolveModuleCallLocation(ctx, file, address, moduleAddress, searchKey, outputLines, location)
		}

		// Nested module not found, try parent modules iteratively
		// Example: "module.vpc.module.subnet" → "module.vpc"
		contextLogger.Debug().
			Str("moduleAddress", moduleAddress).
			Msg("TFPlan: Full nested module not found, trying parent modules")

		if location, found := t.findParentModuleLocation(ctx, file, moduleAddress); found {
			contextLogger.Debug().
				Str("address", address).
				Str("hclFile", location.FilePath).
				Int("line", location.Line).
				Str("tfplanFile", file.FilePath).
				Msg("TFPlan: Found parent module call match in registry")
			return buildVulnerabilityLinesFromLocation(location, outputLines)
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

// resolveModuleCallLocation builds the finding for a searchKey whose address resolved to a
// module call (rather than a root resource): it decides call-site vs. module-definition blame
// using the origin hint, then falls back to module-mapping-based searchKey transformation.
func (t *TFPlanDetectLine) resolveModuleCallLocation(
	ctx context.Context, file *model.FileMetadata, address, moduleAddress, searchKey string, outputLines int,
	location registry.Location,
) model.VulnerabilityLines {
	contextLogger := logger.FromContext(ctx)

	// Determine the target attribute name from the searchKey
	var attrName string
	if parsedKey, err := ParseSearchKey(searchKey); err == nil && len(parsedKey.AttributePath) > 0 {
		attrName = parsedKey.AttributePath[0]
	}

	// Read the origin hint for this attribute to decide call vs definition blame
	origin, varName, moduleDir := extractOriginFromDocument(ctx, file, searchKey, attrName)

	contextLogger.Debug().
		Str("origin", origin).
		Str("varName", varName).
		Str("moduleDir", moduleDir).
		Str("attrName", attrName).
		Msg("TFPlan: Origin hint for attribute")

	// Derive the scan root from the file path of the module call
	scanRoot := filepath.Dir(location.FilePath)

	switch origin {
	case originModuleHardcoded:
		// Blame the module definition: find the resource attribute line inside modules/X/main.tf
		parsed, err := ParseSearchKey(searchKey)
		if err == nil {
			bareAddr := parsed.ResourceType + "." + parsed.ResourceName
			return t.resolveModuleDefinitionLocation(ctx, bareAddr, attrName, moduleDir, scanRoot, outputLines, location)
		}
		// ParseSearchKey failed — fall through to default call-site behavior

	case originModuleDefault:
		// Blame BOTH the variable default AND the module call block (two findings)
		primary, secondary := t.resolveVariableDefaultLocation(ctx, varName, moduleDir, scanRoot, outputLines, location)
		if secondary.ResolvedFile != "" {
			// Attach secondary so the engine fan-out can emit a second finding
			primary.SecondaryLines = &secondary
		}
		return primary
	}

	// origin == "call", "", or unrecognized: existing call-site path
	// Try to transform searchKey using module mappings to find the specific attribute
	// Build full searchKey by combining address with the original searchKey's attribute part
	fullSearchKey := t.buildFullSearchKey(address, searchKey)
	transformedSearchKey, transformedAttrName := t.transformSearchKeyForModule(ctx, moduleAddress, fullSearchKey)

	// Decouple transformation from line lookup:
	// - If transformation succeeds, use the transformed key even if line lookup fails
	// - Only if transformation also succeeds, attempt to find the specific attribute line
	if transformedSearchKey == "" || transformedAttrName == "" {
		// Transformation failed - return module declaration line without transformed key
		contextLogger.Debug().
			Msg("TFPlan: Could not transform searchKey, using module declaration line")
		return buildVulnerabilityLinesFromLocation(location, outputLines)
	}

	contextLogger.Debug().
		Str("originalSearchKey", searchKey).
		Str("transformedSearchKey", transformedSearchKey).
		Str("attributeName", transformedAttrName).
		Msg("TFPlan: Successfully transformed searchKey using module mappings")

	// Try to find the specific attribute line in the module block
	attributeLine := findAttributeLineInFile(location.FilePath, location.Line, transformedAttrName, outputLines, moduleKeyword)
	if attributeLine <= 0 {
		// Line lookup failed, but transformation succeeded
		// Return module declaration line with transformed search key
		contextLogger.Debug().
			Msg("TFPlan: Could not find specific attribute line, using module declaration line with transformed key")
		return buildVulnerabilityLinesFromLocation(location, outputLines, transformedSearchKey)
	}

	contextLogger.Debug().
		Int("attributeLine", attributeLine).
		Msg("TFPlan: Found specific attribute line in module block")

	// Return the attribute line with transformed search key
	attributeLocation := registry.Location{
		FilePath: location.FilePath,
		Line:     attributeLine,
		Column:   location.Column,
	}
	return buildVulnerabilityLinesFromLocation(attributeLocation, outputLines, transformedSearchKey)
}

// findParentModuleLocation walks moduleAddress up to successive parent modules (stripping the
// last "module.<name>" pair each time) until one resolves in the registry.
// Example: "module.vpc.module.subnet" → "module.vpc"
func (t *TFPlanDetectLine) findParentModuleLocation(
	ctx context.Context, file *model.FileMetadata, moduleAddress string,
) (registry.Location, bool) {
	contextLogger := logger.FromContext(ctx)

	parts := strings.Split(moduleAddress, ".")
	for len(parts) >= 2 && parts[len(parts)-2] == moduleKeyword {
		parts = parts[:len(parts)-2]
		if len(parts) == 0 {
			break
		}
		parentModule := strings.Join(parts, ".")

		contextLogger.Debug().
			Str("parentModule", parentModule).
			Msg("TFPlan: Trying parent module")

		if location, found := t.registry.LookupWithScope(parentModule, file.FilePath); found {
			return location, true
		}
	}

	return registry.Location{}, false
}

// extractAddressFromModulePath attempts to find a resource address by searching through all
// resources in the document when the searchKey contains a module path
// Format: module.vpc.aws_instance.bastion or module.app[0].aws_instance.web
func extractAddressFromModulePath(ctx context.Context, file *model.FileMetadata, modulePath string) string {
	contextLogger := logger.FromContext(ctx)

	// Navigate to resource section
	resourceSection, ok := file.LineInfoDocument["resource"]
	if !ok {
		contextLogger.Debug().Msg("No 'resource' section in LineInfoDocument")
		return ""
	}

	resourceMap, ok := resourceSection.(map[string]interface{})
	if !ok {
		return ""
	}

	// We need to search through all resources to find one whose _dd_tf_address matches
	// the module path pattern. The searchKey might be:
	// "module.vpc.aws_instance.bastion.tags" and we need to find a resource whose
	// _dd_tf_address starts with "module.vpc.aws_instance.bastion"

	// Extract the resource path (without the final attribute)
	// module.vpc.aws_instance.bastion.tags → module.vpc.aws_instance.bastion
	parts := strings.Split(modulePath, ".")

	// Try to find where the attribute part starts by looking for common attribute names
	// or by checking if we can match partial paths
	for resourceType, typeSection := range resourceMap {
		typeMap, ok := typeSection.(map[string]interface{})
		if !ok {
			continue
		}

		for resourceKey, resourceAttrs := range typeMap {
			attrsMap, ok := resourceAttrs.(map[string]interface{})
			if !ok {
				continue
			}

			address, ok := attrsMap["_dd_tf_address"]
			if !ok {
				continue
			}

			addressStr, ok := address.(string)
			if !ok {
				continue
			}

			// Check if this address matches our module path
			// The searchKey might have attributes at the end, so we check if the address
			// is a prefix of the search path or if the search path starts with the address
			// IMPORTANT: Use exact match or require addressStr + "." to avoid prefix collisions
			// e.g., "module.x.aws_instance.web" should NOT match "module.x.aws_instance.web_extra"
			isMatch := false
			if modulePath == addressStr {
				// Exact match
				isMatch = true
			} else if strings.HasPrefix(modulePath, addressStr+".") {
				// Prefix match, but require a dot after to avoid collisions
				isMatch = true
			}

			if isMatch {
				contextLogger.Debug().
					Str("modulePath", modulePath).
					Str("matchedAddress", addressStr).
					Str("resourceType", resourceType).
					Str("resourceKey", resourceKey).
					Msg("Found matching address for module path")
				return addressStr
			}

			// Also try the reverse: if the modulePath (without attributes) matches the address
			// This handles cases where searchKey is "module.vpc.aws_instance.bastion.tags"
			// and address is "module.vpc.aws_instance.bastion"
			for i := len(parts); i >= 2; i-- {
				partialPath := strings.Join(parts[:i], ".")
				if partialPath == addressStr {
					contextLogger.Debug().
						Str("modulePath", modulePath).
						Str("partialPath", partialPath).
						Str("matchedAddress", addressStr).
						Msg("Found matching address for partial module path")
					return addressStr
				}
			}
		}
	}

	contextLogger.Debug().
		Str("modulePath", modulePath).
		Msg("No matching address found for module path")
	return ""
}

// extractAddressFromDocument extracts the _dd_tf_address field from the document
// by navigating the searchKey path to find the resource
// Uses the typed ParseSearchKey function for robust parsing
func extractAddressFromDocument(ctx context.Context, file *model.FileMetadata, searchKey string) string {
	contextLogger := logger.FromContext(ctx)

	// Use the typed parser to handle all searchKey formats
	parsed, err := ParseSearchKey(searchKey)
	if err != nil {
		contextLogger.Debug().
			Err(err).
			Str("searchKey", searchKey).
			Msg("Failed to parse searchKey, will try legacy fallback")

		// Fall back to extractAddressFromModulePath for module resources
		if strings.Contains(searchKey, moduleKeyword) {
			return extractAddressFromModulePath(ctx, file, searchKey)
		}
		return ""
	}

	contextLogger.Debug().
		Str("searchKey", searchKey).
		Str("resourceType", parsed.ResourceType).
		Str("resourceName", parsed.ResourceName).
		Bool("isModuleResource", parsed.IsModuleResource).
		Msg("Parsed searchKey with typed parser")

	// For module resources, search through all resources in the document
	// to find one with a matching _dd_tf_address
	// CRITICAL: Documents store NORMALIZED addresses (without indices), so we must search with NormalizedAddr
	// See pkg/parser/json/tfplan.go:96-118 where _dd_tf_address is set to normalizedAddress
	if parsed.IsModuleResource {
		contextLogger.Debug().
			Str("fullAddr", parsed.FullResourceAddr).
			Str("normalizedAddr", parsed.NormalizedAddr).
			Msg("Searching document for module resource address")
		return extractAddressFromModulePath(ctx, file, parsed.NormalizedAddr)
	}

	// For simple resources, navigate directly to the resource
	resourceType := parsed.ResourceType
	resourceKey := parsed.ResourceName

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

	return lookupResourceAddress(ctx, resourceMap, resourceType, resourceKey, searchKey)
}

// lookupResourceAddress navigates resourceMap[resourceType][resourceKey] (falling back to a scan
// by normalized _dd_tf_address for indexed resources) and returns that resource's _dd_tf_address.
func lookupResourceAddress(ctx context.Context, resourceMap map[string]interface{}, resourceType, resourceKey, searchKey string) string {
	contextLogger := logger.FromContext(ctx)

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
	// First try direct lookup (works for non-indexed resources)
	resourceAttrs, ok := typeMap[resourceKey]
	if !ok {
		// Fallback: scan typeMap for matching _dd_tf_address
		// This handles indexed resources where the key is stored as "web[0]"
		// but we're looking up with the normalized name "web"
		contextLogger.Debug().
			Str("resourceType", resourceType).
			Str("resourceKey", resourceKey).
			Msg("Direct lookup failed, scanning for normalized _dd_tf_address")

		normalizedTarget := fmt.Sprintf("%s.%s", resourceType, resourceKey)
		resourceAttrs = findResourceByNormalizedAddress(typeMap, normalizedTarget, &contextLogger)

		// If still not found, return empty
		if resourceAttrs == nil {
			contextLogger.Debug().
				Str("resourceType", resourceType).
				Str("resourceKey", resourceKey).
				Msg("Resource not found even after _dd_tf_address scan")
			return ""
		}
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

	contextLogger.Debug().
		Str("searchKey", searchKey).
		Str("resourceType", resourceType).
		Str("resourceKey", resourceKey).
		Str("extractedAddress", addressStr).
		Msg("Successfully extracted address from document")

	return addressStr
}

// findResourceByNormalizedAddress scans typeMap for a resource whose _dd_tf_address matches
// normalizedTarget, used when the map key itself is index-suffixed (e.g. "web[0]").
func findResourceByNormalizedAddress(typeMap map[string]interface{}, normalizedTarget string, contextLogger *zerolog.Logger) interface{} {
	for key, attrs := range typeMap {
		attrsMap, ok := attrs.(map[string]interface{})
		if !ok {
			continue
		}
		addr, ok := attrsMap["_dd_tf_address"].(string)
		if !ok || addr != normalizedTarget {
			continue
		}
		contextLogger.Debug().
			Str("foundKey", key).
			Str("address", addr).
			Msg("Found resource by _dd_tf_address scan")
		return attrs
	}
	return nil
}

// extractOriginFromDocument reads the _dd_tf_origin hint for a specific attribute from the document.
// It locates the same resource node as extractAddressFromDocument but reads _dd_tf_origin instead.
// Returns (origin, varName, moduleDir) where origin is "call", "module_default", or "module_hardcoded".
//
// When attrName is empty (resource-level finding), it scans ALL attribute hints and returns
// the "most significant" origin: module_hardcoded > module_default > call.
// This handles resource-level Rego queries that flag the entire resource without naming an attribute.
func extractOriginFromDocument(
	ctx context.Context, file *model.FileMetadata, searchKey, attrName string,
) (origin, varName, moduleDir string) {
	contextLogger := logger.FromContext(ctx)

	attrsMap := findResourceAttrsMap(file, searchKey)
	if attrsMap == nil {
		return "", "", ""
	}

	// Read _dd_tf_origin for this attribute
	originMap, ok := attrsMap["_dd_tf_origin"]
	if !ok {
		contextLogger.Debug().Str("attrName", attrName).Msg("TFPlan: No _dd_tf_origin on resource")
		return "", "", ""
	}
	originMapTyped, ok := originMap.(map[string]interface{})
	if !ok {
		return "", "", ""
	}

	if attrName != "" {
		return resolveAttributeOrigin(ctx, originMapTyped, attrName)
	}
	return resolveResourceLevelOrigin(ctx, originMapTyped)
}

// findResourceAttrsMap locates the resource's attributes map in the document by parsing
// searchKey, mirroring extractAddressFromDocument's navigation but returning the raw map
// (needed here to read _dd_tf_origin rather than _dd_tf_address).
func findResourceAttrsMap(file *model.FileMetadata, searchKey string) map[string]interface{} {
	parsed, err := ParseSearchKey(searchKey)
	if err != nil {
		return nil
	}

	resourceSection, ok := file.LineInfoDocument["resource"]
	if !ok {
		return nil
	}
	resourceMap, ok := resourceSection.(map[string]interface{})
	if !ok {
		return nil
	}

	if parsed.IsModuleResource {
		return findResourceAttrsByAddress(resourceMap, parsed.NormalizedAddr)
	}

	typeSection, ok := resourceMap[parsed.ResourceType]
	if !ok {
		return nil
	}
	typeMap, ok := typeSection.(map[string]interface{})
	if !ok {
		return nil
	}
	resourceAttrs, ok := typeMap[parsed.ResourceName]
	if !ok {
		return nil
	}
	attrsMap, ok := resourceAttrs.(map[string]interface{})
	if !ok {
		return nil
	}
	return attrsMap
}

// findResourceAttrsByAddress searches every resource in resourceMap for one whose
// _dd_tf_address equals or is a parent path of normalizedAddr (module resources).
func findResourceAttrsByAddress(resourceMap map[string]interface{}, normalizedAddr string) map[string]interface{} {
	for _, typeSection := range resourceMap {
		typeMap, ok := typeSection.(map[string]interface{})
		if !ok {
			continue
		}
		for _, resourceAttrs := range typeMap {
			am, ok := resourceAttrs.(map[string]interface{})
			if !ok {
				continue
			}
			addr, _ := am["_dd_tf_address"].(string)
			if addr == normalizedAddr || strings.HasPrefix(normalizedAddr, addr+".") {
				return am
			}
		}
	}
	return nil
}

// resolveAttributeOrigin looks up the origin hint for one specific attribute, including a
// dotted-prefix match for nested attributes and a module_hardcoded fallback when the module
// never declared the attribute at all.
func resolveAttributeOrigin(
	ctx context.Context, originMapTyped map[string]interface{}, attrName string,
) (origin, varName, moduleDir string) {
	contextLogger := logger.FromContext(ctx)

	hint, found := originMapTyped[attrName]
	if !found {
		// Try prefix match for nested attributes (e.g. attrName="metadata_options" matches
		// "metadata_options.http_endpoint")
		for key, h := range originMapTyped {
			if strings.HasPrefix(key, attrName+".") {
				hint = h
				found = true
				break
			}
		}
	}
	if !found {
		// The attribute is completely absent from the module resource's expressions — the module
		// never declared it and the call cannot add it. This is module_hardcoded (hardcoded absence).
		// Derive moduleDir from any sibling hint (they all share the same module directory).
		derivedModuleDir := ""
		for _, h := range originMapTyped {
			if hm, ok := h.(map[string]interface{}); ok {
				if d, ok := hm["moduleDir"].(string); ok && d != "" {
					derivedModuleDir = d
					break
				}
			}
		}
		if derivedModuleDir == "" {
			return "", "", ""
		}
		contextLogger.Debug().
			Str("attrName", attrName).
			Str("moduleDir", derivedModuleDir).
			Msg("TFPlan: Attribute absent from module resource expressions — treating as module_hardcoded")
		return originModuleHardcoded, "", derivedModuleDir
	}

	hintMap, ok := hint.(map[string]interface{})
	if !ok {
		return "", "", ""
	}
	origin, _ = hintMap["origin"].(string)
	varName, _ = hintMap["variable"].(string)
	moduleDir, _ = hintMap["moduleDir"].(string)
	return origin, varName, moduleDir
}

// resolveResourceLevelOrigin scans every attribute hint on a resource and returns the most
// significant origin (module_hardcoded > module_default > call), for resource-level Rego
// queries that flag an entire resource without naming an attribute.
func resolveResourceLevelOrigin(ctx context.Context, originMapTyped map[string]interface{}) (origin, varName, moduleDir string) {
	contextLogger := logger.FromContext(ctx)

	originPriority := map[string]int{originModuleHardcoded: 3, originModuleDefault: 2, originCall: 1}

	for _, h := range originMapTyped {
		hintMap, ok := h.(map[string]interface{})
		if !ok {
			continue
		}
		o, _ := hintMap["origin"].(string)
		if originPriority[o] > originPriority[origin] {
			origin = o
			varName, _ = hintMap["variable"].(string)
			moduleDir, _ = hintMap["moduleDir"].(string)
		}
	}

	contextLogger.Debug().
		Str("bestOrigin", origin).
		Str("bestModuleDir", moduleDir).
		Int("hintCount", len(originMapTyped)).
		Msg("TFPlan: Resource-level origin scan result")

	return origin, varName, moduleDir
}

// resolveModuleDefinitionLocation resolves a MODULE_HARDCODED finding to the resource attribute
// line inside the module's own .tf file. Falls back to the module call line on failure.
func (t *TFPlanDetectLine) resolveModuleDefinitionLocation(
	ctx context.Context,
	bareAddr string, // e.g. "aws_db_instance.this"
	attrName string,
	moduleDir string, // relative source path, e.g. "./modules/rds"
	scanRoot string, // absolute path to scan root for resolving moduleDir
	outputLines int,
	callLocation registry.Location, // fallback
) model.VulnerabilityLines {
	contextLogger := logger.FromContext(ctx)

	// Resolve module dir to an absolute path for scoped registry lookup
	scopePath := callLocation.FilePath
	if moduleDir != "" && scanRoot != "" {
		abs := filepath.Join(scanRoot, moduleDir)
		scopePath = filepath.Join(abs, "main.tf") // best-effort scope
	} else if moduleDir != "" && callLocation.FilePath != "" {
		// Resolve relative to the call file's directory
		callFileDir := filepath.Dir(callLocation.FilePath)
		abs := filepath.Join(callFileDir, moduleDir)
		scopePath = filepath.Join(abs, "main.tf")
	}

	defLocation, found := t.registry.LookupWithScope(bareAddr, scopePath)
	if !found {
		contextLogger.Debug().
			Str("bareAddr", bareAddr).
			Str("scopePath", scopePath).
			Msg("TFPlan: MODULE_HARDCODED: resource definition not found in registry, falling back to call site")
		return buildVulnerabilityLinesFromLocation(callLocation, outputLines)
	}

	// Try to refine to the specific attribute line within the resource block
	attrLine := findAttributeLineInFile(defLocation.FilePath, defLocation.Line, attrName, outputLines, "resource")
	if attrLine > 0 {
		attrLocation := registry.Location{
			FilePath: defLocation.FilePath,
			Line:     attrLine,
			Column:   defLocation.Column,
		}
		contextLogger.Debug().
			Str("file", defLocation.FilePath).
			Int("line", attrLine).
			Msg("TFPlan: MODULE_HARDCODED: resolved to resource attribute line")
		return buildVulnerabilityLinesFromLocation(attrLocation, outputLines)
	}

	contextLogger.Debug().
		Str("file", defLocation.FilePath).
		Int("line", defLocation.Line).
		Msg("TFPlan: MODULE_HARDCODED: resolved to resource definition line")
	return buildVulnerabilityLinesFromLocation(defLocation, outputLines)
}

// resolveVariableDefaultLocation resolves a MODULE_DEFAULT finding to the variable's default
// line in variables.tf. Falls back to the variable block line, then the call site.
func (t *TFPlanDetectLine) resolveVariableDefaultLocation(
	ctx context.Context,
	varName string,
	moduleDir string,
	scanRoot string,
	outputLines int,
	callLocation registry.Location, // used as fallback AND as secondary location
) (primary, secondary model.VulnerabilityLines) {
	contextLogger := logger.FromContext(ctx)

	// Build scope path for scoped registry lookup
	scopePath := callLocation.FilePath
	if moduleDir != "" && scanRoot != "" {
		abs := filepath.Join(scanRoot, moduleDir)
		scopePath = filepath.Join(abs, "variables.tf")
	} else if moduleDir != "" && callLocation.FilePath != "" {
		callFileDir := filepath.Dir(callLocation.FilePath)
		abs := filepath.Join(callFileDir, moduleDir)
		scopePath = filepath.Join(abs, "variables.tf")
	}

	varAddr := "var." + varName
	varBlockLocation, found := t.registry.LookupWithScope(varAddr, scopePath)
	if !found {
		contextLogger.Debug().
			Str("varAddr", varAddr).
			Str("scopePath", scopePath).
			Msg("TFPlan: MODULE_DEFAULT: variable block not found in registry, using call site only")
		// Return only the call site finding (no dual-finding possible without the variable location)
		return buildVulnerabilityLinesFromLocation(callLocation, outputLines), model.VulnerabilityLines{}
	}

	// Try to refine to the "default = ..." line within the variable block
	defaultLine := findAttributeLineInFile(varBlockLocation.FilePath, varBlockLocation.Line, "default", outputLines, "variable")
	var primaryLocation registry.Location
	if defaultLine > 0 {
		primaryLocation = registry.Location{
			FilePath: varBlockLocation.FilePath,
			Line:     defaultLine,
			Column:   varBlockLocation.Column,
		}
		contextLogger.Debug().
			Str("file", varBlockLocation.FilePath).
			Int("line", defaultLine).
			Msg("TFPlan: MODULE_DEFAULT: resolved to variable default line")
	} else {
		primaryLocation = varBlockLocation
		contextLogger.Debug().
			Str("file", varBlockLocation.FilePath).
			Int("line", varBlockLocation.Line).
			Msg("TFPlan: MODULE_DEFAULT: resolved to variable block line (no default line found)")
	}

	primaryLines := buildVulnerabilityLinesFromLocation(primaryLocation, outputLines)
	secondaryLines := buildVulnerabilityLinesFromLocation(callLocation, outputLines)
	return primaryLines, secondaryLines
}

// buildVulnerabilityLinesFromLocation creates VulnerabilityLines from a registry Location
func buildVulnerabilityLinesFromLocation(
	location registry.Location, outputLines int, transformedSearchKey ...string,
) model.VulnerabilityLines {
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

	result := model.VulnerabilityLines{
		Line:         location.Line,
		VulnLines:    vulnLines,
		ResolvedFile: location.FilePath,
		VulnerablilityLocation: model.ResourceLocation{
			Start: startLine,
			End:   endLine,
		},
		// Set RemediationLocation to same as VulnerablilityLocation to prevent SARIF line 0 issue
		// See pkg/report/model/sarif.go:598 where empty RemediationLocation can cause invalid locations
		RemediationLocation: model.ResourceLocation{
			Start: startLine,
			End:   endLine,
		},
		ResourceSource: location.FilePath,
		FileSource:     lines, // Actual file contents, not just the path
	}

	// Set transformed search key if provided
	if len(transformedSearchKey) > 0 && transformedSearchKey[0] != "" {
		result.TransformedSearchKey = transformedSearchKey[0]
	}

	return result
}

// NormalizeTFPlanAddress removes all count/for_each indices from a tfplan address
// This is used to match tfplan addresses with HCL-registered addresses
func NormalizeTFPlanAddress(address string) string {
	return registry.NormalizeAddress(address)
}

// buildFullSearchKey combines the address with the searchKey to form a complete path
// For example: address="module.vpc.aws_instance.web", searchKey="aws_instance.web.tags"
// or: address="module.vpc.aws_instance.web", searchKey="module.vpc.aws_instance.web.tags"
// Returns: "module.vpc.aws_instance.web.tags"
func (t *TFPlanDetectLine) buildFullSearchKey(address, searchKey string) string {
	// Use the typed parser to extract attribute information
	parsed, err := ParseSearchKey(searchKey)
	if err != nil {
		// Fall back to simple concatenation if parsing fails
		return address
	}

	// If no attribute, return address as-is
	if !parsed.HasAttribute || len(parsed.AttributePath) == 0 {
		return address
	}

	// Combine address with attribute path
	// For "module.vpc.aws_instance.web.tags.Name", attributePath is ["tags", "Name"]
	attributePart := strings.Join(parsed.AttributePath, ".")
	return address + "." + attributePart
}

// transformSearchKeyForModule attempts to transform a searchKey using module mappings
// For example: "module.vpc.aws_instance.web.tags" → "module.vpc.resource_tags" (if tags maps to resource_tags)
// Returns: (transformedSearchKey, attributeName) where attributeName is the module input variable name
func (t *TFPlanDetectLine) transformSearchKeyForModule(
	ctx context.Context, moduleAddress, searchKey string,
) (transformedSearchKey, attributeName string) {
	contextLogger := logger.FromContext(ctx)

	// No module mappings available
	if t.moduleMappings == nil {
		contextLogger.Debug().Msg("No module mappings available")
		return "", ""
	}

	// Use the typed parser to extract attribute information
	parsed, err := ParseSearchKey(searchKey)
	if err != nil {
		contextLogger.Debug().
			Err(err).
			Str("searchKey", searchKey).
			Msg("Failed to parse searchKey")
		return "", ""
	}

	// Only transform attribute-level findings, not resource-level
	if !parsed.HasAttribute {
		contextLogger.Debug().
			Str("searchKey", searchKey).
			Msg("Resource-level finding, no attribute to transform")
		return "", ""
	}

	// Get the attribute name (first component of attribute path)
	if len(parsed.AttributePath) == 0 {
		contextLogger.Debug().
			Str("searchKey", searchKey).
			Msg("No attribute path found")
		return "", ""
	}

	attributeName = parsed.AttributePath[0]

	// Extract module name from moduleAddress (e.g., "module.vpc" → "vpc")
	// Handle indexed modules: "module.app_servers[0]" → "app_servers"
	moduleParts := strings.Split(moduleAddress, ".")
	if len(moduleParts) < 2 || moduleParts[0] != moduleKeyword {
		contextLogger.Debug().
			Str("moduleAddress", moduleAddress).
			Msg("Invalid module address format")
		return "", ""
	}

	// Extract module name, handling brackets for indexed modules
	moduleName := moduleParts[1]
	if bracketIdx := strings.Index(moduleName, "["); bracketIdx > 0 {
		moduleName = moduleName[:bracketIdx]
	}

	moduleMap, ok := t.lookupModuleMapping(ctx, moduleName)
	if !ok {
		return "", ""
	}

	variableNameStr, status := lookupModuleInputVariable(ctx, moduleMap, parsed.ResourceType, attributeName)
	switch status {
	case moduleInputNotFound:
		// AttributesData/provider/inputs navigation failed outright (non-local module or
		// unexpected shape): fall back to the normalized searchKey to preserve the full
		// resource path and still enable deduplication.
		return searchKey, attributeName
	case moduleInputNonString:
		// The attribute mapping's variable name wasn't a string: fall back to module address + attribute.
		return moduleAddress + "." + attributeName, attributeName
	}

	// Build the transformed searchKey: moduleAddress + variableName
	transformedSearchKey = moduleAddress + "." + variableNameStr

	contextLogger.Debug().
		Str("originalSearchKey", searchKey).
		Str("transformedSearchKey", transformedSearchKey).
		Str("attributeName", attributeName).
		Str("variableName", variableNameStr).
		Msg("Successfully transformed searchKey using module mappings")

	return transformedSearchKey, variableNameStr
}

// moduleInputLookupStatus is the outcome of lookupModuleInputVariable.
type moduleInputLookupStatus int

const (
	moduleInputFound moduleInputLookupStatus = iota
	moduleInputNotFound
	moduleInputNonString
)

// lookupModuleMapping finds moduleName's entry in t.moduleMappings.
// The mapping keys can be:
//   - Just the module name (for local modules)
//   - source::name (for non-local modules to avoid collisions)
//
// It tries the simple name first, then checks all keys that end with ::name (handling the
// same remote module being called multiple times).
func (t *TFPlanDetectLine) lookupModuleMapping(ctx context.Context, moduleName string) (map[string]interface{}, bool) {
	contextLogger := logger.FromContext(ctx)

	moduleData, ok := t.moduleMappings[moduleName]
	if !ok {
		for key, data := range t.moduleMappings {
			if strings.HasSuffix(key, "::"+moduleName) {
				moduleData = data
				ok = true
				contextLogger.Debug().
					Str("moduleName", moduleName).
					Str("matchedKey", key).
					Msg("Found module by source::name key")
				break
			}
		}
	}
	if !ok {
		contextLogger.Debug().
			Str("moduleName", moduleName).
			Msg("Module not found in mappings")
		return nil, false
	}

	moduleMap, ok := moduleData.(map[string]interface{})
	if !ok {
		contextLogger.Debug().
			Str("moduleName", moduleName).
			Str("type", fmt.Sprintf("%T", moduleData)).
			Msg("Module data is not a map")
		return nil, false
	}
	return moduleMap, true
}

// lookupModuleInputVariable navigates moduleMap["AttributesData"][provider]["inputs"][attributeName]
// (provider derived from resourceType's "_"-prefix) to find the module input variable name that
// attributeName maps to. The status return distinguishes "navigation failed" (caller falls back
// to the normalized searchKey) from "found but not a string" (caller falls back differently).
func lookupModuleInputVariable(
	ctx context.Context, moduleMap map[string]interface{}, resourceType, attributeName string,
) (string, moduleInputLookupStatus) {
	contextLogger := logger.FromContext(ctx)
	providerPrefix := strings.Split(resourceType, "_")[0]

	attributesData, ok := moduleMap["AttributesData"]
	if !ok {
		// No AttributesData (non-local module). For example:
		// module.app[0].aws_instance.web.tags → module.app.aws_instance.web.tags
		contextLogger.Debug().
			Str("attributeName", attributeName).
			Msg("No AttributesData in module (likely non-local), using fallback transformation")
		return "", moduleInputNotFound
	}
	attributesMap, ok := attributesData.(map[string]interface{})
	if !ok {
		contextLogger.Debug().
			Str("type", fmt.Sprintf("%T", attributesData)).
			Msg("AttributesData is not a map, using fallback transformation")
		return "", moduleInputNotFound
	}

	providerData, ok := attributesMap[providerPrefix]
	if !ok {
		contextLogger.Debug().
			Str("provider", providerPrefix).
			Msg("Provider not found in module AttributesData, using fallback transformation")
		return "", moduleInputNotFound
	}
	providerMap, ok := providerData.(map[string]interface{})
	if !ok {
		contextLogger.Debug().
			Str("provider", providerPrefix).
			Str("type", fmt.Sprintf("%T", providerData)).
			Msg("Provider data is not a map, using fallback transformation")
		return "", moduleInputNotFound
	}

	inputs, ok := providerMap["inputs"]
	if !ok {
		contextLogger.Debug().
			Str("provider", providerPrefix).
			Msg("No inputs in provider data, using fallback transformation")
		return "", moduleInputNotFound
	}
	inputsMap, ok := inputs.(map[string]interface{})
	if !ok {
		contextLogger.Debug().
			Str("provider", providerPrefix).
			Str("type", fmt.Sprintf("%T", inputs)).
			Msg("Inputs is not a map, using fallback transformation")
		return "", moduleInputNotFound
	}

	variableName, ok := inputsMap[attributeName]
	if !ok {
		contextLogger.Debug().
			Str("attributeName", attributeName).
			Msg("Attribute not found in module inputs, using fallback transformation")
		return "", moduleInputNotFound
	}
	variableNameStr, ok := variableName.(string)
	if !ok {
		contextLogger.Debug().
			Str("attributeName", attributeName).
			Str("type", fmt.Sprintf("%T", variableName)).
			Msg("Variable name is not a string, using fallback transformation")
		return "", moduleInputNonString
	}
	return variableNameStr, moduleInputFound
}

// findAttributeLineInFile searches for an attribute assignment in a block of the given blockType
// using HCL parsing. For module blocks pass blockType="module"; for resource/variable blocks pass
// the respective type name. Returns the line number where the attribute is found, or -1 if not found.
func findAttributeLineInFile(filePath string, startLine int, attributeName string, searchRange int, blockType string) int {
	// Read and parse the HCL file
	content, err := os.ReadFile(filePath) //nolint:gosec // filePath comes from the address registry, scoped to the scan root
	if err != nil {
		return -1
	}

	file, diags := hclsyntax.ParseConfig(content, filePath, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		// Fall back to regex-based search if HCL parsing fails
		return findAttributeLineInFileRegex(filePath, startLine, attributeName, searchRange)
	}

	// Find the block of the requested type that contains the startLine
	var targetBlock *hclsyntax.Block
	for _, block := range file.Body.(*hclsyntax.Body).Blocks {
		if block.Type != blockType {
			continue
		}

		blockRange := block.DefRange()
		// Check if this block contains our start line
		if blockRange.Start.Line <= startLine && blockRange.End.Line >= startLine {
			targetBlock = block
			break
		}
	}

	if targetBlock == nil {
		// Block not found, fall back to regex
		return findAttributeLineInFileRegex(filePath, startLine, attributeName, searchRange)
	}

	// Search for the attribute within the block
	body := targetBlock.Body
	for name, attr := range body.Attributes {
		if name == attributeName {
			return attr.NameRange.Start.Line
		}
	}

	// Attribute not found in this block
	return -1
}

// findAttributeLineInFileRegex is the fallback regex-based search
// Used when HCL parsing fails or as a last resort
func findAttributeLineInFileRegex(filePath string, startLine int, attributeName string, searchRange int) int {
	content, err := os.ReadFile(filePath) //nolint:gosec // filePath comes from the address registry, scoped to the scan root
	if err != nil {
		return -1
	}

	lines := strings.Split(string(content), "\n")
	if startLine < 1 || startLine > len(lines) {
		return -1
	}

	// Search for the attribute in a reasonable range around startLine
	// Module blocks can be large, so we use a generous window
	minSearchWindow := 100
	searchWindow := searchRange * 2
	if searchWindow < minSearchWindow {
		searchWindow = minSearchWindow
	}

	maxLine := startLine + searchWindow
	if maxLine > len(lines) {
		maxLine = len(lines)
	}

	// Pattern to match: "attributeName = ..." or "attributeName=" (with optional spaces)
	attributePattern := fmt.Sprintf(`^\s*%s\s*=`, attributeName)

	for i := startLine - 1; i < maxLine; i++ {
		line := lines[i]
		matched, _ := regexp.MatchString(attributePattern, line)
		if matched {
			return i + 1 // Return 1-indexed line number
		}
	}

	return -1
}
