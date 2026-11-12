/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	pathpkg "path"
	"path/filepath"

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

// moduleFileCalls are the evaluated calls reaching an external module file. A
// finding raised on the file as written is reported once per call.
type moduleFileCalls struct {
	calls []moduleCall
	name  string
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
func (idx *moduleCallIndex) fileCalls() map[string]*moduleFileCalls {
	if idx == nil || len(idx.calls) == 0 {
		return nil
	}
	out := make(map[string]*moduleFileCalls)
	for dir, calls := range idx.calls {
		for _, f := range idx.files[dir] {
			out[f.ID] = &moduleFileCalls{
				calls: calls,
				name:  filepath.Base(f.FilePath),
			}
		}
	}
	return out
}

// attributeModuleFileFindings reports each finding raised on an external
// module file as written once per call reaching it, at that call's site.
// Findings already attributed to a call are kept as they are.
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

// dropUnattributedExternalFindings removes the findings on an external module
// file that no call accounts for. The file is not part of the scanned
// repository, so such a finding has no location to report.
func dropUnattributedExternalFindings(vulns []model.Vulnerability, external func(string) bool) []model.Vulnerability {
	if external == nil {
		return vulns
	}
	var kept []model.Vulnerability
	for i := range vulns {
		v := &vulns[i]
		if v.ModuleAttribution == nil && external(v.FileName) {
			if kept == nil {
				kept = append(make([]model.Vulnerability, 0, len(vulns)-1), vulns[:i]...)
			}
			continue
		}
		if kept != nil {
			kept = append(kept, *v)
		}
	}
	if kept == nil {
		return vulns
	}
	return kept
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
