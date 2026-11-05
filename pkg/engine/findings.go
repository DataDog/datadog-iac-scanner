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
// Routing runs before the identity is recorded. It gives a finding the call
// chain of each module caller it stands for (for a finding identified by its
// Terraform address, the caller's root module, and for an external module
// file the call's module address), and two instances that share an identity
// can stand for different callers. Recording the identity first would drop
// the callers of every instance but the first.
type findingSet struct {
	out     []model.Vulnerability
	routing *findingRouting
	// kept maps the identities of the findings in out to their index. Nil
	// when the set is not reducing by identity, so every finding is appended.
	kept map[[sha256.Size]byte]int
	// detectedOn holds, for each finding in out, the document its line was
	// detected on, which routing does not change.
	detectedOn []string
	keyBuf     []byte
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
	// Routing changes only the call chain of what goes into the identity, or
	// the root module and address of a finding identified by them.
	id, lineFree := model.IdentityBeforeLine(v)
	for i := range routed {
		r := &routed[i]
		var digest [sha256.Size]byte
		switch tid, ok := model.TerraformIdentityOf(r); {
		case ok:
			s.keyBuf = model.AppendTerraformIdentity(s.keyBuf[:0], utils.ChooseQueryID(r.QueryID, r.LegacyQueryID), tid)
			digest = sha256.Sum256(s.keyBuf)
		case lineFree:
			s.keyBuf = id.AppendWithChain(s.keyBuf[:0], r.ModuleCallChain)
			digest = sha256.Sum256(s.keyBuf)
		default:
			digest = sha256.Sum256([]byte(model.FindingIdentity(r)))
		}
		s.keep(digest, r, v.FileID)
	}
}

// keep records v, detected on document docID, unless a finding of identity
// digest that comes first is kept.
func (s *findingSet) keep(digest [sha256.Size]byte, v *model.Vulnerability, docID string) {
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

// resultIdentity identifies the findings of a result before its line is
// detected.
type resultIdentity struct {
	resourceType, resourceName string
	// chained is the identity of a finding identified by its file, resource
	// and module call chain.
	chained model.ChainedIdentity
	// id is the Terraform identity of a finding identified by its address,
	// when addressed is set.
	id        model.TerraformIdentity
	addressed bool
	ruleID    string
	// docID, fileName and searchKey are where the result was raised, set by
	// supersedes.
	docID, fileName, searchKey string
}

// newResultIdentity is the identity of the findings of a result raised on file,
// before its line is detected: the Terraform identity the vulnerability
// builder attaches when addresses is set and the block resolves (the address
// comes from the block, not the line), the chained identity otherwise. known
// is false when the identity includes the line.
func newResultIdentity(
	file *model.FileMetadata, addresses bool, platform, resourceType, resourceName, queryID, legacyQueryID string,
) (r resultIdentity, known bool) {
	r = resultIdentity{resourceType: resourceType, resourceName: resourceName}
	if addresses && platform == model.TerraformPlatform {
		if r.id, r.addressed = terraformIdentityFor(file, resourceType, resourceName); r.addressed {
			r.ruleID = utils.ChooseQueryID(queryID, legacyQueryID)
			return r, true
		}
	}
	r.chained, known = model.ChainedIdentityFor(file.FilePath, platform, resourceType, resourceName, queryID, legacyQueryID)
	return r, known
}

// supersedes reports whether routing result r, raised on file at searchKey,
// would only produce identities this set already kept on a finding that comes
// first, so the result cannot change the report. Its line is not known yet,
// so a finding kept on the same file comes first only when it was raised at
// the same search key on a document built from the same written file: the
// instances of one block detect the same location there, and nothing else
// model.CompareFindings reads tells two findings of one identity apart.
//
// It has to agree with findingRouting.route in that direction (see
// TestFindingSet_SupersedesMeansRouteKeepsNothingNew). The as-written
// identity is required only when routing can produce it: an external module
// file that is reported only through its calls does not.
func (s *findingSet) supersedes(r *resultIdentity, file *model.FileMetadata, searchKey string) bool {
	if file == nil || len(s.kept) == 0 {
		return false
	}
	r.docID, r.fileName, r.searchKey = file.ID, file.FilePath, searchKey
	if !s.accounted(r, file.ID, file.ModuleCallChain, r.id, len(file.ModuleAttributions) > 0) {
		return false
	}
	if s.routing == nil {
		return true
	}
	for _, ex := range s.routing.extras[file.ID] {
		id := r.id
		if r.addressed {
			id.RootModule = ex.rootModule
		}
		if !s.accounted(r, ex.docID, ex.callChain, id, len(ex.attributions) > 0) {
			return false
		}
	}
	return true
}

// accounted reports whether every identity routing can give a finding raised
// on document fileID and reported under chain, or under Terraform identity id,
// is already kept.
func (s *findingSet) accounted(
	r *resultIdentity, fileID, chain string, id model.TerraformIdentity, attributionPossible bool,
) bool {
	var file *moduleFileCalls
	if s.routing != nil {
		file = s.routing.moduleFiles[fileID]
	}
	if file == nil || file.keptAsWritten(r.resourceType) {
		return s.hasRoute(r, chain, id)
	}
	var block address.Block
	var blockOK bool
	if r.addressed {
		block, blockOK = file.routedBlock(id, r.resourceType, r.resourceName)
	}
	// The calls are produced unless the line attributes the finding. The line
	// is not known yet, so every call has to be kept already.
	for i := range file.calls {
		call := &file.calls[i]
		callID := id
		if blockOK {
			callID = file.callIdentity(call, block)
		}
		if !s.hasRoute(r, call.callChain, callID) {
			return false
		}
	}
	// Kept as written, or attributed from the line. Without attributions the
	// as-written finding is not produced, and requiring it would never skip.
	if file.keepWritten || attributionPossible {
		return s.hasRoute(r, chain, id)
	}
	return true
}

// hasRoute reports whether the finding of r routed under chain, or under
// Terraform identity id when r is addressed, is already kept on a finding
// that comes first.
func (s *findingSet) hasRoute(r *resultIdentity, chain string, id model.TerraformIdentity) bool {
	if r.addressed {
		s.keyBuf = model.AppendTerraformIdentity(s.keyBuf[:0], r.ruleID, id)
	} else {
		s.keyBuf = r.chained.AppendWithChain(s.keyBuf[:0], chain)
	}
	i, ok := s.kept[sha256.Sum256(s.keyBuf)]
	if !ok {
		return false
	}
	kept := &s.out[i]
	return kept.FileName < r.fileName ||
		(kept.FileName == r.fileName && kept.SearchKey == r.searchKey &&
			writtenFileID(s.detectedOn[i]) == writtenFileID(r.docID))
}

// findings returns what the set kept and empties the set.
func (s *findingSet) findings() []model.Vulnerability {
	out := s.out
	s.out, s.kept, s.detectedOn, s.keyBuf = nil, nil, nil, nil
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
}

// newFindingRouting indexes the caller files once for the whole scan. The
// rules route concurrently, so the index is built before any of them run.
func newFindingRouting(
	extras map[string][]extraCallerInfo, moduleFiles map[string]*moduleFileCalls,
	files model.FileMetadatas, repoPath string,
) *findingRouting {
	callers := make(map[string]*model.FileMetadata)
	for _, f := range files {
		if f == nil || f.ModuleCallChain != "" || isSyntheticTerraformDoc(f) {
			continue
		}
		key := repoRelativeFile(f.FilePath, repoPath)
		if _, ok := callers[key]; !ok {
			callers[key] = f
		}
	}
	return &findingRouting{extras: extras, moduleFiles: moduleFiles, callers: callers}
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
	vulns = expandModuleFindings(vulns, r.extras)
	vulns = attributeModuleFileFindings(vulns, r.moduleFiles)
	return c.filterAtCallSites(ctx, vulns, r.callers)
}
