/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"crypto/sha256"
	"iter"
	"slices"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
)

// findingSet collects the findings of one rule as they are decoded and
// routed, optionally keeping one per identity.
//
// The scan reports the last finding of each identity (see
// model.FindingIdentity), and a module instantiated per count or for_each
// instance raises the same finding once per instance: one rule can raise
// hundreds of thousands of findings that the report then collapses to a few
// thousand. Keeping each identity's latest finding as they are decoded gives
// the report the same findings without holding the others until the scan ends.
//
// That reduction is only valid for a caller that, like storage, keeps the
// last finding of each identity (see Inspector.SetCompactFindingsAtDecode).
//
// A compacting set is given the rule's results last raised first, so the
// finding it keeps is the first one it is given. A result whose every
// identity is already kept can then be skipped before its line is detected
// (see supersedes).
//
// Routing runs before the identity is recorded. It gives a finding the root
// module of each caller it stands for, and for an external module file the
// module address of each call reaching it, and two callers can share one
// identity only when the report collapses them too. Recording the identity
// first would drop the callers of every instance but the last.
type findingSet struct {
	out     []model.Vulnerability
	routing *findingRouting
	// kept holds the identities of the findings in out. Nil when the set is
	// not reducing by identity, so every finding is appended.
	kept map[[sha256.Size]byte]struct{}
}

// newFindingSet starts a set that reduces findings to one per identity when
// compact is true, or keeps every finding it is given when compact is false.
// routing, which may be nil, routes each finding before it is kept.
func newFindingSet(compact bool, routing *findingRouting) *findingSet {
	s := &findingSet{routing: routing}
	if compact {
		s.kept = make(map[[sha256.Size]byte]struct{})
	}
	return s
}

// lastRaisedFirst reports whether the set must be given the rule's results
// from the last one raised to the first.
func (s *findingSet) lastRaisedFirst() bool {
	return s != nil && s.kept != nil
}

// maySkip reports whether a result could be dropped before its line is
// detected. The first result of a rule cannot: nothing is kept yet.
func (s *findingSet) maySkip() bool {
	return s != nil && len(s.kept) > 0
}

// order yields the positions of a rule's n results in the order the set must
// be given them.
func (s *findingSet) order(n int) iter.Seq[int] {
	lastFirst := s.lastRaisedFirst()
	return func(yield func(int) bool) {
		for k := 0; k < n; k++ {
			i := k
			if lastFirst {
				i = n - 1 - k
			}
			if !yield(i) {
				return
			}
		}
	}
}

// addRouted routes v to the module callers it stands for and keeps what
// routing produced. A compacting set, given results last raised first, keeps
// the first finding of each identity.
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
	// the identity is recomputed per routed copy rather than once from v (see
	// K9CODESEC-7158).
	for i := len(routed) - 1; i >= 0; i-- {
		s.keep(model.FindingIdentity(&routed[i]), &routed[i])
	}
}

// keep records v unless its identity is already kept.
func (s *findingSet) keep(id string, v *model.Vulnerability) {
	digest := sha256.Sum256([]byte(id))
	if _, ok := s.kept[digest]; ok {
		return
	}
	s.kept[digest] = struct{}{}
	s.out = append(s.out, *v)
}

// supersedes reports whether routing a result with the given identities
// would only produce identities this set already kept, so the result cannot
// change the report. An empty entry is an identity routing does not produce
// (a module file reported only through its calls keeps no as-written
// finding). It has to agree with findingRouting.route in that direction (see
// TestFindingSet_SupersedesMeansRouteKeepsNothingNew).
func (s *findingSet) supersedes(identities []string) bool {
	if len(s.kept) == 0 {
		return false
	}
	for _, id := range identities {
		if id != "" && !s.has(id) {
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
		// Without a resolved identity the finding falls back to the legacy
		// fingerprint, which routing no longer changes (a routed copy without
		// an address hashes like the as-written one).
		legacy, known := model.IdentityInputFor(file.FilePath, platform, resourceType, resourceName, queryID, legacyQueryID)
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
	routedAway := mf != nil && !mf.keptAsWritten(resourceType) && !mf.keepWritten && !attributionPossible
	if !routedAway {
		*ids = append(*ids, terraformIdentityInput(ruleID, id))
	}
	if s.routing == nil {
		return
	}
	for _, ex := range s.routing.extras[docID] {
		s.appendRouteIdentities(ids, ruleID, resourceType, ex.docID, scope, block,
			model.TerraformIdentity{RootModule: ex.rootModule, ResourceID: id.ResourceID},
			len(ex.attributions) > 0)
	}
	// An identical-content instance member reports the same blocks at its own
	// instance keys. Like route's expandInstanceFindings, a member identity is
	// only produced for a finding on an expanded block both the primary's and
	// the member's scope carry (see instanceMemberIdentity).
	if (address.Block{}) != block {
		s.appendInstanceMemberIdentities(ids, ruleID, docID, scope, block)
	}
	if mf != nil && !mf.keptAsWritten(resourceType) {
		for i := range mf.calls {
			call := &mf.calls[i]
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
}

// terraformIdentityInput builds the fingerprint input of a Terraform finding
// from its resolved identity and rule, the exact input model.FindingIdentity
// hashes (the repo is constant within a scan).
func terraformIdentityInput(ruleID string, id model.TerraformIdentity) string {
	input, _ := model.IdentityInput("", terraformPlatformValue, "", "", ruleID, id)
	return input
}

func (s *findingSet) has(id string) bool {
	_, ok := s.kept[sha256.Sum256([]byte(id))]
	return ok
}

// findings returns what the set kept, in the order the rule raised it, and
// empties the set. A compacting set is given its results last raised first,
// so this reverses them.
func (s *findingSet) findings() []model.Vulnerability {
	out := s.out
	if s.lastRaisedFirst() {
		slices.Reverse(out)
	}
	s.out, s.kept = nil, nil
	return out
}

// findingRouting is what turns the findings a rule raises on the scanned
// documents into the findings of the scan: the callers a deduplicated module
// document stands for, the identical-content instance documents folded into a
// primary's, the calls reaching an external module file, and the caller files
// whose filters apply to module findings.
type findingRouting struct {
	extras         map[string][]extraCallerInfo
	instanceExtras map[string][]extraInstanceInfo
	moduleFiles    map[string]*moduleFileCalls
	callers        map[string]*model.FileMetadata
}

// newFindingRouting indexes the caller files once for the whole scan. The
// rules route concurrently, so the index is built before any of them run.
func newFindingRouting(
	extras map[string][]extraCallerInfo, instanceExtras map[string][]extraInstanceInfo,
	moduleFiles map[string]*moduleFileCalls,
	files model.FileMetadatas, repoPath string,
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
	return &findingRouting{extras: extras, instanceExtras: instanceExtras, moduleFiles: moduleFiles, callers: callers}
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
	vulns = expandInstanceFindings(vulns, r.instanceExtras)
	vulns = attributeModuleFileFindings(vulns, r.moduleFiles)
	return c.filterAtCallSites(ctx, vulns, r.callers)
}

// expandInstanceFindings clones the findings of an all-instances primary
// document onto every identical-content member instance, rewriting each
// finding's address with the member's instance suffix. Everything else —
// message, lines, severity, rule — is identical by construction: the members
// resolved byte-identical attributes and share the defining file, so their
// line detection resolves the same text.
//
// Only a finding whose block is one of the expanded instances is cloned: a
// finding that names no declared block has no instance address to rewrite and
// keeps the legacy fingerprint, which is the same for every member (they
// share the defining file), so the report collapses them as it does today.
func expandInstanceFindings(
	vulns []model.Vulnerability, extras map[string][]extraInstanceInfo,
) []model.Vulnerability {
	if len(extras) == 0 {
		return vulns
	}
	expanded := make([]model.Vulnerability, 0, len(vulns))
	for i := range vulns {
		members := extras[vulns[i].FileID]
		if len(members) == 0 {
			expanded = append(expanded, vulns[i])
			continue
		}
		expanded = append(expanded, vulns[i])
		// Every member carries the same blocks as the primary, so the primary's
		// scope resolves the finding's block for all of them.
		scope := members[0].scope
		block, ok := resolveTerraformBlock(scope, vulns[i].ResourceType, vulns[i].ResourceName)
		if !ok {
			continue
		}
		if _, instanced := scope.Instances[block]; !instanced {
			continue
		}
		for _, m := range members {
			vCopy := vulns[i]
			if suffix, ok := m.instances[block]; ok {
				vCopy.ResourceID = address.Instance(scope.ModuleAddress, block, suffix)
			} else {
				// Unreachable for content-identical members; keep the primary's
				// address rather than inventing one.
				vCopy.ResourceID = vulns[i].ResourceID
			}
			vCopy.RootModule = m.rootModule
			vCopy.FileID = m.docID
			expanded = append(expanded, vCopy)
		}
	}
	return expanded
}

// instanceMemberIdentity returns the identity a member instance document
// reports for a finding on block b of the primary's scope: the member's root
// module and the block's address at the member's instance key. ok is false
// when the block is not one of the member's instances, in which case the
// member reports nothing new for the finding (route's expandInstanceFindings
// does not clone it either — the two must agree, see supersedes).
func instanceMemberIdentity(
	scope *model.TerraformScope, b address.Block, member extraInstanceInfo,
) (model.TerraformIdentity, bool) {
	if suffix, ok := member.instances[b]; ok {
		return model.TerraformIdentity{
			RootModule: member.rootModule,
			ResourceID: address.Instance(scope.ModuleAddress, b, suffix),
		}, true
	}
	return model.TerraformIdentity{}, false
}

// appendInstanceMemberIdentities appends the identity each identical-content
// instance member would report for a finding raised on docID's block: the
// member's root module and the block's address at the member's instance key.
// A finding on a block outside the primary's instances map reports nothing
// per member (see instanceMemberIdentity).
func (s *findingSet) appendInstanceMemberIdentities(
	ids *[]string, ruleID, docID string, scope *model.TerraformScope, block address.Block,
) {
	for _, ex := range s.routing.instanceExtras[docID] {
		if id, ok := instanceMemberIdentity(scope, block, ex); ok {
			*ids = append(*ids, terraformIdentityInput(ruleID, id))
		}
	}
}
