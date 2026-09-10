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

func New() *AddressRegistry {
	return &AddressRegistry{
		mappings: make(map[string][]Location),
	}
}

// Register adds an address->location mapping to the registry
func (r *AddressRegistry) Register(address string, location Location) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	normalizedAddr := NormalizeAddress(address)

	existingLocations := r.mappings[normalizedAddr]
	for _, existing := range existingLocations {
		if existing.FilePath == location.FilePath && existing.Line == location.Line {
			return
		}
	}

	r.mappings[normalizedAddr] = append(existingLocations, location)

	if len(r.mappings[normalizedAddr]) > 1 {
		log.Debug().
			Str("address", normalizedAddr).
			Int("locationCount", len(r.mappings[normalizedAddr])).
			Str("newFile", location.FilePath).
			Int("newLine", location.Line).
			Msg("Multiple locations registered for address - will use scope-based disambiguation")
	}
}

// LookupWithScope retrieves the best location for a given address based on the scope file path
// When multiple locations exist (e.g., module "vpc" in different directories), chooses the one
// in the same directory or closest common ancestor to the scope file
func (r *AddressRegistry) LookupWithScope(address, scopeFilePath string) (Location, bool) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	normalizedAddr := NormalizeAddress(address)

	locations := r.mappings[normalizedAddr]
	if len(locations) == 0 {
		return Location{}, false
	}

	if len(locations) == 1 {
		return locations[0], true
	}

	return chooseBestLocation(locations, scopeFilePath), true
}

func (r *AddressRegistry) GetLocationCount(address string) int {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	normalizedAddr := NormalizeAddress(address)
	return len(r.mappings[normalizedAddr])
}

func (r *AddressRegistry) HasDuplicates(address string) bool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

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

// commonPathLength scores how well path1's directory matches path2's (the scope file), comparing
// whole path segments rather than raw characters. This keeps a file's own directory ranked above
// a sibling directory whose name happens to share a character prefix with the scope file's name
// (e.g. scope "/project/plan.tfplan.json" must not outscore "/project/main.tf" against
// "/project/plan/resource.tf" just because "plan" is a literal substring of the scope).
// An exact directory match always outranks a partial prefix match, even a deep one: matching all
// of a shorter path's components against a longer path's leading components (a parent/child
// directory relationship) is still a worse match than the two directories being identical.
// Only the directory is compared; the filename itself doesn't participate in disambiguation.
func commonPathLength(path1, path2 string) int {
	dir1 := cleanDir(path1)
	dir2 := cleanDir(path2)

	if dir1 == dir2 {
		// +1 so an exact match at depth N always beats a prefix match of depth N,
		// which can score at most N (see the loop below).
		return len(strings.Split(dir1, "/")) + 1
	}

	parts1 := strings.Split(dir1, "/")
	parts2 := strings.Split(dir2, "/")
	minLen := min(len(parts2), len(parts1))

	common := 0
	for i := 0; i < minLen; i++ {
		if parts1[i] != parts2[i] {
			break
		}
		common++
	}

	return common
}

// cleanDir returns the directory portion of path, with backslashes normalized to forward
// slashes and no trailing slash.
func cleanDir(path string) string {
	path = strings.ReplaceAll(path, "\\", "/")
	dir := path[:strings.LastIndex(path, "/")+1]
	return strings.TrimSuffix(dir, "/")
}

func (r *AddressRegistry) Clear() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.mappings = make(map[string][]Location)
}

func (r *AddressRegistry) GetMappingCount() int {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return len(r.mappings)
}

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

// NormalizeAddress removes all count/for_each indices from an address.
// Quote- and escape-aware, since a for_each string key can itself contain a
// literal "]" (e.g. module.secrets["prod]eu"].aws_instance.web).
// Examples:
//   - "module.vpc[0].aws_instance.web[1]" -> "module.vpc.aws_instance.web"
//   - "aws_instance.app["prod"]" -> "aws_instance.app"
//   - "module.network["us-east-1"].module.subnet[0]" -> "module.network.module.subnet"
//   - `module.secrets["prod]eu"].aws_instance.web` -> "module.secrets.aws_instance.web"
func NormalizeAddress(address string) string {
	var result strings.Builder
	depth := 0
	inQuotes := false

	for i := 0; i < len(address); i++ {
		c := address[i]
		switch {
		case c == '\\' && inQuotes:
			i++
		case c == '"':
			inQuotes = !inQuotes
		case c == '[' && !inQuotes:
			depth++
		case c == ']' && !inQuotes:
			if depth > 0 {
				depth--
			}
		case depth == 0:
			result.WriteByte(c)
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
	normalized := NormalizeAddress(address)

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
