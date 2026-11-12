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
	callChain string
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
	// writtenResourceTypes are resource types still in the file after instantiation.
	writtenResourceTypes map[string]bool
	// resolvedInBody are blocks evaluation resolved and left in the file because
	// no rule names their type. kind -> base name.
	resolvedInBody map[string]map[string]bool
	// keepWritten records that some calls of the directory were not evaluated.
	keepWritten bool
}

// moduleCallIndex collects the evaluated calls of the directories holding
// external module files. A nil index collects nothing.
type moduleCallIndex struct {
	external func(string) bool
	files    map[string][]*model.FileMetadata
	calls    map[string][]moduleCall
	// resolvedInBody is file ID -> block kind -> base name, for resources
	// evaluation resolved and did not re-emit because no rule names the type.
	resolvedInBody map[string]map[string]map[string]bool
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

// noteResolvedInBody records a block evaluation resolved and left in the file.
func (idx *moduleCallIndex) noteResolvedInBody(fileID, kind, name string) {
	if idx == nil || fileID == "" || kind == "" || name == "" {
		return
	}
	if idx.resolvedInBody == nil {
		idx.resolvedInBody = make(map[string]map[string]map[string]bool)
	}
	byKind := idx.resolvedInBody[fileID]
	if byKind == nil {
		byKind = make(map[string]map[string]bool)
		idx.resolvedInBody[fileID] = byKind
	}
	names := byKind[kind]
	if names == nil {
		names = make(map[string]bool)
		byKind[kind] = names
	}
	names[name] = true
}

// record attributes each call of an indexed directory. cache must belong to
// the root the instances were evaluated from.
func (idx *moduleCallIndex) record(
	instances []tfeval.ModuleInstance,
	repoPath string,
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
			callChain:   moduleCallChainKey(instance.CallChain, instance.ModuleAddress, repoPath),
			attribution: attr,
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
				calls:          calls,
				name:           filepath.Base(f.FilePath),
				keepWritten:    unresolvedDirs[dir],
				resolvedInBody: idx.resolvedInBody[f.ID],
			}
		}
	}
	return out
}

// documentResourceTypes returns the resource types a parsed file declares,
// and its data types prefixed with "data.", as findings name them.
func documentResourceTypes(doc model.Document) map[string]bool {
	resources, hasResources := asStringMap(doc["resource"])
	data, hasData := asStringMap(doc["data"])
	if !hasResources && !hasData {
		return nil
	}
	types := make(map[string]bool)
	for typ := range resources {
		types[typ] = true
	}
	for typ := range data {
		types[dataTypePrefix+typ] = true
	}
	return types
}

// keptAsWritten reports whether the finding's resource type is still scanned
// where it is written. A data rule may name its type without the "data."
// prefix, as moduleAttributionForResource allows.
func (f *moduleFileCalls) keptAsWritten(resourceType string) bool {
	if f.anyResolvedInBody(resourceType) {
		return false
	}
	return f.typeStillWritten(resourceType)
}

func (f *moduleFileCalls) typeStillWritten(resourceType string) bool {
	if f.writtenResourceTypes[resourceType] {
		return true
	}
	if strings.HasPrefix(resourceType, dataTypePrefix) {
		return false
	}
	return f.writtenResourceTypes[dataTypePrefix+resourceType]
}

// leftUninstantiated reports a block still in the file that evaluation did not resolve.
func (f *moduleFileCalls) leftUninstantiated(resourceType, resourceName string) bool {
	if !f.typeStillWritten(resourceType) {
		return false
	}
	if f.resolvedName(resourceType, resourceName) {
		return false
	}
	if resourceName == "" && f.anyResolvedInBody(resourceType) {
		return false
	}
	return true
}

func (f *moduleFileCalls) anyResolvedInBody(resourceType string) bool {
	return len(f.resolvedNames(resourceType)) > 0
}

func (f *moduleFileCalls) resolvedName(resourceType, resourceName string) bool {
	names := f.resolvedNames(resourceType)
	if len(names) == 0 || resourceName == "" {
		return false
	}
	return names[tfeval.ResourceBaseName(resourceName)]
}

func (f *moduleFileCalls) resolvedNames(resourceType string) map[string]bool {
	if names := f.resolvedInBody[resourceType]; len(names) > 0 {
		return names
	}
	if strings.HasPrefix(resourceType, dataTypePrefix) {
		return nil
	}
	return f.resolvedInBody[dataTypePrefix+resourceType]
}

// attributeModuleFileFindings reports each finding raised on an external
// module file once per call reaching it. A block evaluation did not resolve
// is dropped. A block it resolved and left in the file, because no rule names
// the type, is reported at the call.
func attributeModuleFileFindings(vulns []model.Vulnerability, files map[string]*moduleFileCalls) []model.Vulnerability {
	if len(files) == 0 {
		return vulns
	}
	var out []model.Vulnerability
	for i := range vulns {
		v := &vulns[i]
		file := files[v.FileID]
		if file == nil || v.ModuleAttribution != nil {
			if out != nil {
				out = append(out, *v)
			}
			continue
		}
		if out == nil {
			out = make([]model.Vulnerability, i, len(vulns)+len(file.calls))
			copy(out, vulns[:i])
		}
		if file.leftUninstantiated(v.ResourceType, v.ResourceName) {
			continue
		}
		for j := range file.calls {
			call := &file.calls[j]
			attributed := *v
			attributed.ModuleCallChain = call.callChain
			attributed.ModuleAttribution = moduleFileAttribution(call.attribution, file.name, v)
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
