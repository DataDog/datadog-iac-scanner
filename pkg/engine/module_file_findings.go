/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"maps"
	pathpkg "path"
	"path/filepath"
	"slices"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	tfmodel "github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
)

// moduleCall is one evaluated call of a module directory.
type moduleCall struct {
	callChain string
	// moduleAddress and rootModule are detached from the evaluated model. They
	// let static written findings receive the same per-caller address as legacy.
	moduleAddress string
	rootModule    string
	// attribution names the directory in ModuleCodeLocation.Filename. It is
	// shared by every file of the directory and read-only.
	attribution *model.ModuleAttribution
}

// moduleFileCalls are the evaluated calls reaching an external module file. A
// finding raised on the file as written is reported once per call.
type moduleFileCalls struct {
	calls []moduleCall
	name  string
	file  *model.FileMetadata
}

// moduleCallIndex collects the evaluated calls of the directories holding
// external module files. A nil index collects nothing.
type moduleCallIndex struct {
	mu       sync.Mutex
	external func(string) bool
	files    map[string][]*model.FileMetadata
	calls    map[string][]moduleCall
}

// newModuleCallIndex indexes the directories of the files external reports,
// or returns nil when there are none.
func newModuleCallIndex(files map[string]*model.FileMetadata, external func(string) bool) *moduleCallIndex {
	if external == nil {
		return nil
	}
	idx := &moduleCallIndex{
		external: external,
		files:    make(map[string][]*model.FileMetadata),
		calls:    make(map[string][]moduleCall),
	}
	for _, path := range slices.Sorted(maps.Keys(files)) {
		f := files[path]
		if f != nil && external(f.FilePath) {
			dir := filepath.Clean(filepath.Dir(path))
			idx.files[dir] = append(idx.files[dir], f)
		}
	}
	if len(idx.files) == 0 {
		return nil
	}
	return idx
}

// recordModules records the concrete module instances retained by a modeled
// root. Static blocks are projected once per directory, while their written
// findings belong to every resolved call that reaches the directory.
func (idx *moduleCallIndex) recordModules(
	modules []*tfmodel.Module,
	repoPath string,
	chainBase string,
	attribution *terraformAttribution,
) {
	if idx == nil || attribution == nil {
		return
	}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	for _, instance := range modules {
		if instance == nil || instance.Address == "" || len(instance.Chain) == 0 {
			continue
		}
		if _, ok := tfeval.ModuleTerraformAddress(instance.Chain); !ok {
			continue
		}
		dir := filepath.Clean(instance.Dir)
		if _, ok := idx.files[dir]; !ok {
			continue
		}
		attribution.mu.Lock()
		attr := callAttribution(instance.Chain, dir, repoPath, attribution.lookup, attribution.cache)
		attribution.mu.Unlock()
		if attr == nil {
			continue
		}
		rootModule := ""
		if instance.Root != nil {
			rootModule = repoRelativeDir(instance.Root.Dir, chainBase, nil)
		}
		idx.calls[dir] = append(idx.calls[dir], moduleCall{
			callChain:     legacyModuleCallChainKey(instance.Chain, instance.Address, chainBase),
			moduleAddress: instance.Address,
			rootModule:    rootModule,
			attribution:   attr,
		})
	}
}

// fileCalls returns the calls reaching each indexed file, by file ID.
func (idx *moduleCallIndex) fileCalls() map[string]*moduleFileCalls {
	if idx == nil {
		return nil
	}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	if len(idx.calls) == 0 {
		return nil
	}
	out := make(map[string]*moduleFileCalls)
	for dir, calls := range idx.calls {
		for _, f := range idx.files[dir] {
			out[f.ID] = &moduleFileCalls{
				calls: calls,
				name:  filepath.Base(f.FilePath),
				file:  f,
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
			attachModuleCallAddress(file.file, &attributed, *call)
			out = append(out, attributed)
		}
	}
	if out == nil {
		return vulns
	}
	return out
}

// attachModuleCallAddress supplies TerraformScope for this one caller without
// changing the scanned file's scope or retaining the evaluated module tree.
func attachModuleCallAddress(file *model.FileMetadata, v *model.Vulnerability, call moduleCall) {
	if file == nil || call.moduleAddress == "" {
		return
	}
	scopedFile := *file
	scope := model.TerraformScope{}
	if file.TerraformScope != nil {
		scope = *file.TerraformScope
	}
	scope.ModuleAddress = call.moduleAddress
	scope.RootModule = call.rootModule
	scopedFile.TerraformScope = &scope
	attachTerraformAddress(&scopedFile, v, "")
}

// dropUnattributedExternalFindings removes the findings on an external module
// file that no call accounts for. The file is not part of the scanned
// repository, so such a finding has no location to report.
func dropUnattributedExternalFindings(
	vulns []model.Vulnerability,
	callers map[string]*model.FileMetadata,
	external func(string) bool,
	knownRemote func(string) bool,
) []model.Vulnerability {
	if external == nil {
		return vulns
	}
	var kept []model.Vulnerability
	for i := range vulns {
		v := &vulns[i]
		if !external(v.FileName) || externalFindingHasScannedCaller(v, callers, knownRemote) {
			if kept != nil {
				kept = append(kept, *v)
			}
			continue
		}
		if kept == nil {
			kept = append(make([]model.Vulnerability, 0, len(vulns)-1), vulns[:i]...)
		}
	}
	if kept == nil {
		return vulns
	}
	return kept
}

func externalFindingHasScannedCaller(
	v *model.Vulnerability,
	callers map[string]*model.FileMetadata,
	knownRemote func(string) bool,
) bool {
	if v.ModuleAttribution == nil {
		return false
	}
	key := filepath.ToSlash(filepath.Clean(v.ModuleAttribution.CallSite.Filename))
	caller, ok := callers[key]
	return ok && caller != nil && (knownRemote == nil || !knownRemote(caller.FilePath))
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
