/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"crypto/sha256"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
)

// findingSet collects the findings of one rule as they are decoded and
// routed, optionally keeping one per identity.
//
// The scan reports one finding per identity (see model.FindingIdentity), the
// first in model.CompareFindings order, and a module instantiated per count
// or for_each instance raises the same finding once per instance: one rule
// can raise hundreds of thousands of findings that the report then collapses
// to a few thousand. Keeping each identity's first finding as they are
// decoded gives the report the same findings without holding the others
// until the scan ends.
//
// That reduction is only valid for a caller that keeps one finding per
// identity (see Inspector.SetCompactFindingsAtDecode).
//
// A result that cannot come before what is kept for each of its identities
// can be skipped before its line is detected (see supersedes).
//
// Routing runs before the identity is recorded. It gives a finding the root
// module of each caller it stands for, and for an external module file the
// module address of each call reaching it, and two callers can share one
// identity only when the report collapses them too. Recording the identity
// first would drop the callers of every instance but the last.
type findingSet struct {
	out     []model.Vulnerability
	routing *findingRouting
	// kept maps the identities of the findings in out to their index. Nil
	// when the set is not reducing by identity, so every finding is appended.
	kept map[[sha256.Size]byte]int
	// detectedOn holds, for each finding in out, the document its line was
	// detected on, which routing does not change.
	detectedOn []string
}

// newFindingSet starts a set that reduces findings to one per identity when
// compact is true, or keeps every finding it is given when compact is false.
// routing, which may be nil, routes each finding before it is kept.
func newFindingSet(compact bool, routing *findingRouting) *findingSet {
	s := &findingSet{routing: routing}
	if compact {
		s.kept = make(map[[sha256.Size]byte]int)
	}
	return s
}

// maySkip reports whether a result could be dropped before its line is
// detected. The first result of a rule cannot: nothing is kept yet.
func (s *findingSet) maySkip() bool {
	return s != nil && len(s.kept) > 0
}

// addRouted routes v to the module callers it stands for and keeps what
// routing produced. A compacting set keeps the first finding of each identity
// in model.CompareFindings order.
func (s *findingSet) addRouted(ctx context.Context, c *Inspector, v *model.Vulnerability) {
	var routed []model.Vulnerability
	if s.routing == nil {
		routed = []model.Vulnerability{*v}
	} else {
		routed = s.routing.route(ctx, c, []model.Vulnerability{*v})
	}
	if s.kept == nil {
		s.out = append(s.out, routed...)
		return
	}
	// Routing changes the root module directory, and for a finding on an
	// external module file the address, of what goes into the identity:
	// different callers of the same module path are different root stacks, so
	// the identity is recomputed per routed copy rather than once from v.
	for i := range routed {
		s.keep(model.FindingIdentity(&routed[i]), &routed[i], v.FileID)
	}
}

// keep records v, detected on document docID, unless a finding of its
// identity that comes first is kept.
func (s *findingSet) keep(id string, v *model.Vulnerability, docID string) {
	digest := sha256.Sum256([]byte(id))
	if i, ok := s.kept[digest]; ok {
		if model.CompareFindings(v, &s.out[i]) < 0 {
			s.out[i] = *v
			s.detectedOn[i] = docID
		}
		return
	}
	s.kept[digest] = len(s.out)
	s.out = append(s.out, *v)
	s.detectedOn = append(s.detectedOn, docID)
}

// supersedes reports whether routing a result of document docID, reported
// on fileName at searchKey, with the given identities, would only produce
// identities this set already kept on a finding that comes first, so the
// result cannot change the report. Its line is not known yet, so a finding
// kept on the same file comes first only when it was raised on the same
// document at the same search key. An empty entry is an identity routing
// does not produce (a module file reported only through its calls keeps no
// as-written finding). It has to agree with findingRouting.route in that
// direction (see TestFindingSet_SupersedesMeansRouteKeepsNothingNew).
func (s *findingSet) supersedes(identities []string, docID, fileName, searchKey string) bool {
	if len(s.kept) == 0 {
		return false
	}
	for _, id := range identities {
		if id == "" {
			continue
		}
		i, ok := s.kept[sha256.Sum256([]byte(id))]
		if !ok {
			return false
		}
		kept := &s.out[i]
		first := kept.FileName < fileName ||
			(kept.FileName == fileName && s.detectedOn[i] == docID && kept.SearchKey == searchKey)
		if !first {
			return false
		}
	}
	return true
}

// findingIdentities returns the identities a result raised on file with this
// resourceType and resourceName would produce: one per finding routing keeps,
// in the order route produces them. An empty entry is an identity routing
// does not produce (see supersedes). ok is false when the identity cannot be
// known before the line is detected (a Dockerfile finding).
func (s *findingSet) findingIdentities(
	file *model.FileMetadata, platform, resourceType, resourceName, queryID, legacyQueryID string,
) ([]string, bool) {
	ruleID := utils.ChooseQueryID(queryID, legacyQueryID)
	id, resolved := terraformIdentityFor(file, resourceType, resourceName)
	if platform != terraformPlatformValue || file.TerraformScope == nil || !resolved {
		// Without a resolved identity the finding keys on the resource-name
		// fingerprint, which routing does not change (a routed copy without
		// an address hashes like the as-written one).
		legacy, known := model.IdentityInput(file.FilePath, platform, resourceType, resourceName, ruleID,
			model.TerraformIdentity{CallChain: file.ModuleCallChain})
		return []string{legacy}, known
	}
	var block address.Block
	if file.Kind != model.KindTerraformPlan {
		block, _ = terraformBlockFor(file, resourceType, resourceName)
	}
	var ids []string
	s.appendRouteIdentities(&ids, ruleID, resourceType, file.ID, file.TerraformScope, block, id,
		len(file.ModuleAttributions) > 0)
	return ids, true
}

func (s *findingSet) runRoot() string {
	if s.routing == nil {
		return ""
	}
	return s.routing.runRoot
}

// appendRouteIdentities appends the identities routing produces for a finding
// with identity id raised on document docID (scoped by scope, its block by
// block): the finding itself, unless an external-module-file route replaces
// it, then one per extra caller and one per call reaching an external module
// file — recursively, since an extra caller may itself be an external module
// file whose copies route through its own calls.
func (s *findingSet) appendRouteIdentities(
	ids *[]string, ruleID, resourceType, docID string,
	scope *model.TerraformScope, block address.Block, id model.TerraformIdentity,
	attributionPossible bool,
) {
	var mf *moduleFileCalls
	if s.routing != nil {
		mf = s.routing.moduleFiles[docID]
	}
	run := s.runRoot()
	routedAway := mf != nil && !mf.keptAsWritten(resourceType) && !mf.keepWritten && !attributionPossible
	if !routedAway && reportsRoot(run, id.RootModule) {
		*ids = append(*ids, terraformIdentityInput(ruleID, id))
	}
	if s.routing == nil {
		return
	}
	s.appendExtraIdentities(ids, ruleID, resourceType, docID, scope, block, id, run)
	s.appendCallIdentities(ids, ruleID, mf, resourceType, scope, block, id, run)
}

func (s *findingSet) appendExtraIdentities(
	ids *[]string, ruleID, resourceType, docID string,
	scope *model.TerraformScope, block address.Block, id model.TerraformIdentity, run string,
) {
	for _, ex := range s.routing.extras[docID] {
		if !reportsRoot(run, ex.rootModule) {
			continue
		}
		s.appendRouteIdentities(ids, ruleID, resourceType, ex.docID, scope, block,
			model.TerraformIdentity{RootModule: ex.rootModule, ResourceID: id.ResourceID},
			len(ex.attributions) > 0)
	}
}

func (s *findingSet) appendCallIdentities(
	ids *[]string, ruleID string, mf *moduleFileCalls, resourceType string,
	scope *model.TerraformScope, block address.Block, id model.TerraformIdentity, run string,
) {
	if mf == nil || mf.keptAsWritten(resourceType) {
		return
	}
	for i := range mf.calls {
		call := &mf.calls[i]
		if !reportsRoot(run, call.rootModule) {
			continue
		}
		resourceID := id.ResourceID
		if call.moduleAddress != "" {
			resourceID = call.moduleAddress + "." + resourceID
		}
		if (address.Block{}) != block {
			resourceID = routedBlockAddress(scope, block, call.moduleAddress)
		}
		*ids = append(*ids, terraformIdentityInput(ruleID, model.TerraformIdentity{
			RootModule: call.rootModule,
			ResourceID: resourceID,
		}))
	}
}

// reportsRoot reports whether a copy whose root is root belongs to this run.
// A copy with no root is kept: the evaluation produced it and named no other root.
func reportsRoot(run, root string) bool {
	return run == "" || root == "" || root == run
}

// terraformIdentityInput builds the fingerprint input of a Terraform finding
// from its resolved identity and rule, the exact input model.FindingIdentity
// hashes (the repo is constant within a scan).
func terraformIdentityInput(ruleID string, id model.TerraformIdentity) string {
	input, _ := model.IdentityInput("", terraformPlatformValue, "", "", ruleID, id)
	return input
}

// findings returns what the set kept and empties the set.
func (s *findingSet) findings() []model.Vulnerability {
	out := s.out
	s.out, s.kept, s.detectedOn = nil, nil, nil
	return out
}

// findingRouting is what turns the findings a rule raises on the scanned
// documents into the findings of the scan: the callers a deduplicated module
// document stands for, the calls reaching an external module file, and the
// caller files whose filters apply to module findings.
type findingRouting struct {
	extras      map[string][]extraCallerInfo
	moduleFiles map[string]*moduleFileCalls
	callers     map[string]*model.FileMetadata
	docRoots    map[string][]string
	// runRoot limits a cross-document evaluation to one root. Empty keeps every caller.
	runRoot string
	// rootExtras and rootModuleFiles are extras and moduleFiles limited to
	// runRoot, built once by forRoot; they are nil when runRoot is empty.
	rootExtras      map[string][]extraCallerInfo
	rootModuleFiles map[string]*moduleFileCalls
}

// newFindingRouting indexes the caller files once for the whole scan. The
// rules route concurrently, so the index is built before any of them run.
func newFindingRouting(
	extras map[string][]extraCallerInfo, moduleFiles map[string]*moduleFileCalls,
	docRoots map[string][]string, files model.FileMetadatas, repoPath string,
) *findingRouting {
	callers := make(map[string]*model.FileMetadata)
	for _, f := range files {
		if f == nil || isSyntheticTerraformDoc(f) {
			continue
		}
		key := repoRelativeFile(f.FilePath, repoPath)
		if _, ok := callers[key]; !ok {
			callers[key] = f
		}
	}
	return &findingRouting{extras: extras, moduleFiles: moduleFiles, callers: callers, docRoots: docRoots}
}

// forRoot returns routing that reports only this root's copies. The maps stay shared.
func (r *findingRouting) forRoot(root string) *findingRouting {
	if r == nil || root == "" {
		return r
	}
	cp := *r
	cp.runRoot = root
	cp.rootExtras = extrasForRoot(r.extras, root)
	cp.rootModuleFiles = moduleFilesForRoot(r.moduleFiles, root)
	return &cp
}

// route turns one rule's decoded findings into the findings the scan reports
// for them. It runs per rule rather than over the whole scan so the copies it
// makes are a rule's findings rather than every finding of the scan.
func (r *findingRouting) route(
	ctx context.Context, c *Inspector, vulns []model.Vulnerability,
) []model.Vulnerability {
	if r == nil {
		return vulns
	}
	extras, moduleFiles := r.extras, r.moduleFiles
	if r.runRoot != "" {
		extras, moduleFiles = r.rootExtras, r.rootModuleFiles
	}
	vulns = expandModuleFindings(vulns, extras)
	vulns = attributeModuleFileFindings(vulns, moduleFiles)
	if r.runRoot != "" {
		vulns = vulnsForRoot(vulns, r.runRoot)
	}
	return c.filterAtCallSites(ctx, vulns, r.callers)
}

func extrasForRoot(extras map[string][]extraCallerInfo, root string) map[string][]extraCallerInfo {
	if len(extras) == 0 {
		return extras
	}
	out := make(map[string][]extraCallerInfo)
	for id, list := range extras {
		for _, ex := range list {
			if ex.rootModule == root {
				out[id] = append(out[id], ex)
			}
		}
	}
	return out
}

func moduleFilesForRoot(files map[string]*moduleFileCalls, root string) map[string]*moduleFileCalls {
	if len(files) == 0 {
		return files
	}
	out := make(map[string]*moduleFileCalls, len(files))
	for id, mf := range files {
		if mf == nil {
			continue
		}
		cp := *mf
		cp.calls = nil
		for i := range mf.calls {
			if mf.calls[i].rootModule == root {
				cp.calls = append(cp.calls, mf.calls[i])
			}
		}
		out[id] = &cp
	}
	return out
}

func vulnsForRoot(vulns []model.Vulnerability, root string) []model.Vulnerability {
	out := make([]model.Vulnerability, 0, len(vulns))
	for i := range vulns {
		if reportsRoot(root, vulns[i].RootModule) {
			out = append(out, vulns[i])
		}
	}
	return out
}
