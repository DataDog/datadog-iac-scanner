/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	pathpkg "path"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
)

// moduleCall is one evaluated call of a module directory.
type moduleCall struct {
	// moduleAddress is the call's module instance address, keys included
	// (K9CODESEC-7158): a resource in the module is reported under it, so two
	// instances of one call never share a fingerprint.
	moduleAddress string
	// rootModule is the caller's root module directory, repository-relative.
	rootModule string
	// attribution names the directory in ModuleCodeLocation.Filename. It is
	// shared by every file of the directory and read-only.
	attribution *model.ModuleAttribution
}

// moduleFileCalls are the evaluated calls reaching an external module file.
// Blocks other than resources are not instantiated per call, so their findings
// are raised once on the file as written and reported once per call.
type moduleFileCalls struct {
	calls []moduleCall
	name  string
	// scope is the file's Terraform identity context: the as-written block
	// addresses a finding routed to a call is prefixed with (K9CODESEC-7158).
	scope *model.TerraformScope
	// writtenResourceTypes are the resource types still scanned where they are
	// written, the blocks evaluation did not instantiate. Their findings keep
	// standing for those blocks as written.
	writtenResourceTypes map[string]bool
	// keepWritten keeps each finding as written too, standing for the calls of
	// the directory evaluation did not reach.
	keepWritten bool
}

// moduleCallIndex collects the evaluated calls of the directories holding
// external module files. A nil index collects nothing.
type moduleCallIndex struct {
	external func(string) bool
	files    map[string][]*model.FileMetadata
	calls    map[string][]moduleCall
}

// newModuleCallIndex indexes the directories of the files external reports,
// or returns nil when there are none.
func newModuleCallIndex(filesByDir map[string][]*model.FileMetadata, external func(string) bool) *moduleCallIndex {
	if external == nil {
		return nil
	}
	idx := &moduleCallIndex{
		external: external,
		files:    make(map[string][]*model.FileMetadata),
		calls:    make(map[string][]moduleCall),
	}
	for dir, files := range filesByDir {
		for _, f := range files {
			if external(f.FilePath) {
				idx.files[dir] = append(idx.files[dir], f)
			}
		}
	}
	if len(idx.files) == 0 {
		return nil
	}
	return idx
}

// record attributes each call of an indexed directory. cache must belong to
// the root the instances were evaluated from.
func (idx *moduleCallIndex) record(
	instances []tfeval.ModuleInstance,
	repoPath string,
	relDir func(string) string,
	lookup moduleProvenanceLookup,
	cache *moduleAttributionCache,
) {
	if idx == nil {
		return
	}
	for i := range instances {
		instance := &instances[i]
		dir := filepath.Clean(instance.Dir)
		if _, ok := idx.files[dir]; !ok {
			continue
		}
		// A directory no scanned file calls is only reached from other
		// external modules, so there is no call site in the scanned code.
		if len(instance.CallChain) == 0 || idx.external(instance.CallChain[0].CalledFrom) {
			continue
		}
		attr := callAttribution(instance.CallChain, dir, repoPath, lookup, cache)
		if attr == nil {
			continue
		}
		idx.calls[dir] = append(idx.calls[dir], moduleCall{
			moduleAddress: instance.ModuleAddress,
			rootModule:    relDir(filepath.Dir(absPath(instance.CallChain[0].CalledFrom, repoPath))),
			attribution:   attr,
		})
	}
}

// fileCalls returns the calls reaching each indexed file, by file ID.
func (idx *moduleCallIndex) fileCalls(unresolvedDirs map[string]bool) map[string]*moduleFileCalls {
	if idx == nil || len(idx.calls) == 0 {
		return nil
	}
	out := make(map[string]*moduleFileCalls)
	for dir, calls := range idx.calls {
		for _, f := range idx.files[dir] {
			out[f.ID] = &moduleFileCalls{
				calls:       calls,
				name:        filepath.Base(f.FilePath),
				scope:       f.TerraformScope,
				keepWritten: unresolvedDirs[dir],
			}
		}
	}
	return out
}

// documentResourceTypes returns the resource types a parsed file declares,
// its data and ephemeral types prefixed as findings name them.
func documentResourceTypes(doc model.Document) map[string]bool {
	resources, hasResources := asStringMap(doc["resource"])
	data, hasData := asStringMap(doc["data"])
	ephemeral, hasEphemeral := asStringMap(doc[ephemeralSection])
	if !hasResources && !hasData && !hasEphemeral {
		return nil
	}
	types := make(map[string]bool)
	for typ := range resources {
		types[typ] = true
	}
	for typ := range data {
		types[dataTypePrefix+typ] = true
	}
	for typ := range ephemeral {
		types[ephemeralPrefix+typ] = true
	}
	return types
}

// keptAsWritten reports whether the finding's resource type is still scanned
// where it is written. A data rule may name its type without the "data."
// prefix, as moduleAttributionForResource allows.
func (f *moduleFileCalls) keptAsWritten(resourceType string) bool {
	if f.writtenResourceTypes[resourceType] {
		return true
	}
	if strings.HasPrefix(resourceType, dataTypePrefix) {
		return false
	}
	return f.writtenResourceTypes[dataTypePrefix+resourceType]
}

// attributeModuleFileFindings reports each finding raised on an external
// module file as written once per call reaching it, at that call's site.
// Findings already attributed to a call, and those on resource blocks left as
// written, are kept as they are.
func attributeModuleFileFindings(vulns []model.Vulnerability, files map[string]*moduleFileCalls) []model.Vulnerability {
	if len(files) == 0 {
		return vulns
	}
	var out []model.Vulnerability
	for i := range vulns {
		v := &vulns[i]
		file := files[v.FileID]
		if file == nil || v.ModuleAttribution != nil || file.keptAsWritten(v.ResourceType) {
			if out != nil {
				out = append(out, *v)
			}
			continue
		}
		if out == nil {
			out = make([]model.Vulnerability, i, len(vulns)+len(file.calls))
			copy(out, vulns[:i])
		}
		if file.keepWritten {
			out = append(out, *v)
		}
		for j := range file.calls {
			call := &file.calls[j]
			attributed := *v
			attributed.ModuleAttribution = moduleFileAttribution(call.attribution, file.name, v)
			// The copy stands for the block as written under this call's
			// module instance address and the caller's root module, so two
			// instances of one call get distinct fingerprints
			// (K9CODESEC-7158).
			attributed.RootModule = call.rootModule
			if file.scope != nil {
				if block, ok := resolveTerraformBlock(file.scope, v.ResourceType, v.ResourceName); ok {
					attributed.ResourceID = routedBlockAddress(file.scope, block, call.moduleAddress)
				}
			}
			out = append(out, attributed)
		}
	}
	if out == nil {
		return vulns
	}
	return out
}

// moduleFileAttribution returns the call's attribution with its code location
// at the finding inside the file named name.
func moduleFileAttribution(call *model.ModuleAttribution, name string, v *model.Vulnerability) *model.ModuleAttribution {
	attr := cloneModuleAttribution(call)
	attr.ModuleCodeLocation = model.SourceLocation{
		Filename:    pathpkg.Join(call.ModuleCodeLocation.Filename, name),
		LineStart:   v.Line,
		LineEnd:     v.Line,
		ColumnStart: 1,
		ColumnEnd:   2,
	}
	narrowCodeLocation(&attr.ModuleCodeLocation, v)
	return attr
}
