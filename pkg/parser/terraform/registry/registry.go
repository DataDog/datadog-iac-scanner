/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package registry

import (
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

// moduleKeyword is the "module" path segment in a dotted Terraform address.
const moduleKeyword = "module"

// Location represents a location in a source file
type Location struct {
	FilePath string
	Line     int
	Column   int
}

// AddressRegistry stores mappings from Terraform addresses to source locations
// Multiple locations can exist for the same address (e.g., module "vpc" in different directories)
type AddressRegistry struct {
	mutex    sync.RWMutex
	mappings map[string][]Location // Stores ALL locations per address
}

// New creates a new instance of AddressRegistry
func New() *AddressRegistry {
	return &AddressRegistry{
		mappings: make(map[string][]Location),
	}
}

// Register adds an address->location mapping to the registry
// Multiple locations with the same address are stored (e.g., module "vpc" in different directories)
func (r *AddressRegistry) Register(address string, location Location) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Normalize the address (remove any indices)
	normalizedAddr := NormalizeAddress(address)

	// Check if this exact location is already registered (same file and line)
	existingLocations := r.mappings[normalizedAddr]
	for _, existing := range existingLocations {
		if existing.FilePath == location.FilePath && existing.Line == location.Line {
			// Already registered, skip
			return
		}
	}

	// Add this location to the list
	r.mappings[normalizedAddr] = append(existingLocations, location)

	// Log when multiple locations exist for the same address
	if len(r.mappings[normalizedAddr]) > 1 {
		log.Debug().
			Str("address", normalizedAddr).
			Int("locationCount", len(r.mappings[normalizedAddr])).
			Str("newFile", location.FilePath).
			Int("newLine", location.Line).
			Msg("Multiple locations registered for address - will use scope-based disambiguation")
	}
}

// Lookup retrieves a location for a given address
// If multiple locations exist, returns the first one (for backward compatibility)
// For better disambiguation, use LookupWithScope
func (r *AddressRegistry) Lookup(address string) (Location, bool) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Normalize the address before lookup
	normalizedAddr := NormalizeAddress(address)

	locations := r.mappings[normalizedAddr]
	if len(locations) == 0 {
		return Location{}, false
	}
	return locations[0], true
}

// LookupWithScope retrieves the best location for a given address based on the scope file path
// When multiple locations exist (e.g., module "vpc" in different directories), chooses the one
// in the same directory or closest common ancestor to the scope file
func (r *AddressRegistry) LookupWithScope(address, scopeFilePath string) (Location, bool) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Normalize the address before lookup
	normalizedAddr := NormalizeAddress(address)

	locations := r.mappings[normalizedAddr]
	if len(locations) == 0 {
		return Location{}, false
	}

	// If only one location, return it
	if len(locations) == 1 {
		return locations[0], true
	}

	// Multiple locations - choose the best match based on scope
	return chooseBestLocation(locations, scopeFilePath), true
}

// GetLocationCount returns the number of locations for a given address
func (r *AddressRegistry) GetLocationCount(address string) int {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	normalizedAddr := NormalizeAddress(address)
	return len(r.mappings[normalizedAddr])
}

// HasDuplicates checks if an address was registered multiple times from different locations
func (r *AddressRegistry) HasDuplicates(address string) bool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Normalize the address before checking
	normalizedAddr := NormalizeAddress(address)

	return len(r.mappings[normalizedAddr]) > 1
}

// chooseBestLocation selects the best location from multiple candidates based on scope
// Prefers locations in the same directory as scopeFilePath, then closest common ancestor
func chooseBestLocation(locations []Location, scopeFilePath string) Location {
	if len(locations) == 0 {
		return Location{}
	}
	if len(locations) == 1 {
		return locations[0]
	}

	// Strategy: Choose the location with the longest common path prefix with scope
	// This prefers files in the same directory over files in different directories

	bestLocation := locations[0]
	bestScore := commonPathLength(bestLocation.FilePath, scopeFilePath)

	for _, loc := range locations[1:] {
		score := commonPathLength(loc.FilePath, scopeFilePath)
		if score > bestScore {
			bestScore = score
			bestLocation = loc
		}
	}

	return bestLocation
}

// commonPathLength returns the length of the common path prefix between two file paths
// Example: "/a/b/c/file1.tf" and "/a/b/d/file2.tf" returns 4 (length of "/a/b/")
func commonPathLength(path1, path2 string) int {
	// Normalize paths to use forward slashes
	path1 = strings.ReplaceAll(path1, "\\", "/")
	path2 = strings.ReplaceAll(path2, "\\", "/")

	minLen := len(path1)
	if len(path2) < minLen {
		minLen = len(path2)
	}

	commonLen := 0
	for i := 0; i < minLen; i++ {
		if path1[i] == path2[i] {
			commonLen++
		} else {
			break
		}
	}

	return commonLen
}

// Clear removes all mappings (useful for testing)
func (r *AddressRegistry) Clear() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.mappings = make(map[string][]Location)
}

// GetMappingCount returns the number of registered mappings (for testing/debugging)
func (r *AddressRegistry) GetMappingCount() int {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return len(r.mappings)
}

// GetDuplicateCount returns the number of addresses that have multiple locations (for testing/debugging)
func (r *AddressRegistry) GetDuplicateCount() int {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	count := 0
	for _, locations := range r.mappings {
		if len(locations) > 1 {
			count++
		}
	}
	return count
}

// NormalizeAddress removes all count/for_each indices from an address
// Examples:
//   - "module.vpc[0].aws_instance.web[1]" -> "module.vpc.aws_instance.web"
//   - "aws_instance.app["prod"]" -> "aws_instance.app"
//   - "module.network["us-east-1"].module.subnet[0]" -> "module.network.module.subnet"
func NormalizeAddress(address string) string {
	var result strings.Builder
	inBracket := false

	for _, char := range address {
		switch char {
		case '[':
			inBracket = true
		case ']':
			inBracket = false
		default:
			if !inBracket {
				result.WriteRune(char)
			}
		}
	}

	return result.String()
}

// ExtractModuleAddress extracts just the module part from a full address
// Examples:
//   - "module.vpc.aws_instance.web" -> "module.vpc"
//   - "module.network.module.subnet.aws_subnet.private" -> "module.network.module.subnet"
//   - "aws_instance.web" -> "" (no module)
//   - "module.vpc" -> "" (just a module without resources)
func ExtractModuleAddress(address string) string {
	// First normalize to remove indices
	normalized := NormalizeAddress(address)

	// Split by dots
	parts := strings.Split(normalized, ".")

	// If we only have module.name (2 parts), this is just a module reference, not a resource in a module
	if len(parts) == 2 && parts[0] == moduleKeyword {
		return ""
	}

	// Build the module path by looking for all "module.name" pairs
	var moduleParts []string
	i := 0
	for i < len(parts)-1 {
		if parts[i] == moduleKeyword {
			// Found a module declaration, add module and its name
			moduleParts = append(moduleParts, parts[i], parts[i+1])
			i += 2 // Skip both "module" and the name
			// Continue looking for more nested modules
		} else {
			// Hit a non-module part (likely resource type), stop here
			break
		}
	}

	return strings.Join(moduleParts, ".")
}
