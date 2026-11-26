/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"crypto/sha256"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// findingSet collects the findings of one rule as they are decoded and
// routed, optionally keeping one per identity.
//
// A compacting set keeps the first finding of each identity in
// model.CompareFindings order, the same finding storage reports (see
// Inspector.SetCompactFindingsAtDecode). The scan reports the first finding
// of each identity (see model.FindingIdentity), and a module instantiated per
// count or for_each instance raises the same finding once per instance: one
// rule can raise hundreds of thousands of findings that the report then
// collapses to a few thousand. Keeping each identity's first finding as they
// are decoded gives the report the same findings without holding the others
// until the scan ends.
//
// That reduction is only valid for a caller that, like storage, keeps the
// first finding of each identity in CompareFindings order and drops the rest.
// It must stay off for a caller that reads Inspect's return value directly,
// such as the test-rules rule harness, because identity does not include the
// line for most platforms and collapsing at decode would silently drop a
// second genuine violation of one resource.
//
// Routing runs before the identity is recorded. Two instances that share an
// identity can stand for different callers, and recording the identity first
// would drop the callers of every instance but the first.
type findingSet struct {
	out     []model.Vulnerability
	routing *findingRouting
	// kept maps the identities of the findings in out to their index. Nil
	// when the set is not reducing by identity, so every finding is appended.
	kept   map[[sha256.Size]byte]int
	keyBuf []byte
	// recordDuplicates merges occurrence references by finding identity.
	// The union is assigned once, after the reporting winner is known.
	recordDuplicates bool
	occurrences      map[int]model.OccurrenceSet
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

// addRouted routes v to the module callers it stands for and keeps what
// routing produced. A compacting set keeps, of the findings sharing an
// identity, the first one in model.CompareFindings order.
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
	// Routing changes only the call chain of what goes into the identity.
	id, lineFree := model.IdentityBeforeLine(v)
	for i := range routed {
		r := &routed[i]
		var digest [sha256.Size]byte
		if lineFree {
			s.keyBuf = id.AppendWithChain(s.keyBuf[:0], r.ModuleCallChain)
			digest = sha256.Sum256(s.keyBuf)
		} else {
			digest = sha256.Sum256([]byte(model.FindingIdentity(r)))
		}
		s.keep(digest, r)
	}
}

// keep records v, unless the set already keeps a finding of identity digest
// that comes first in model.CompareFindings order.
func (s *findingSet) keep(digest [sha256.Size]byte, v *model.Vulnerability) {
	if i, ok := s.kept[digest]; ok {
		if s.recordDuplicates && (len(v.ResourceOccurrences) > 0 || len(s.out[i].ResourceOccurrences) > 0) {
			if s.occurrences == nil {
				s.occurrences = make(map[int]model.OccurrenceSet)
			}
			p := s.occurrences[i]
			if p == nil {
				p = model.OccurrenceSet{}
				p.Add(&s.out[i])
				s.occurrences[i] = p
			}
			p.Add(v)
		}
		if model.CompareFindings(v, &s.out[i]) < 0 {
			s.out[i] = *v
		}
		return
	}
	s.kept[digest] = len(s.out)
	s.out = append(s.out, *v)
}

// findings returns what the set kept and empties the set.
func (s *findingSet) findings() []model.Vulnerability {
	for i, p := range s.occurrences {
		p.Assign(&s.out[i])
	}
	out := s.out
	s.out, s.kept, s.keyBuf, s.occurrences = nil, nil, nil, nil
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
	occurrences documentOccurrenceIndex
	// external includes both fetched paths and files outside the repository.
	// Every routing instance has this predicate, including scans without a cache.
	external func(string) bool
}

// newFindingRouting indexes the caller files once for the whole scan. The
// rules route concurrently, so the index is built before any of them run.
func newFindingRouting(
	extras map[string][]extraCallerInfo, moduleFiles map[string]*moduleFileCalls,
	files model.FileMetadatas, repoPath string, external func(string) bool,
) *findingRouting {
	outside := externalModuleFiles(repoPath, external)
	callers := make(map[string]*model.FileMetadata)
	for _, f := range files {
		if f == nil || f.ModuleCallChain != "" || outside(f.FilePath) {
			continue
		}
		key, local := repositoryFileName(f.FilePath, repoPath)
		if !local {
			continue
		}
		if _, ok := callers[key]; !ok {
			callers[key] = f
		}
	}
	return &findingRouting{extras: extras, moduleFiles: moduleFiles, callers: callers, external: outside}
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
	vulns = expandModuleFindings(vulns, r.extras, r.occurrences)
	vulns = attributeModuleFileFindings(vulns, r.moduleFiles)
	kept := vulns[:0]
	for i := range vulns {
		v := &vulns[i]
		caller, reportable := r.resolveLocation(v)
		if !reportable {
			continue
		}
		if caller != nil {
			if rc, found := lookupRuleConfig(c.ruleConfigs, v.QueryID, v.LegacyQueryID, v.LegacyQueryIDs); found &&
				rulePathExcluded(caller.FilePath, rc.IgnorePaths, rc.OnlyPaths) {
				contextLogger := logger.FromContext(ctx)
				contextLogger.Debug().Msgf("Dropping module finding called from %s for rule %s (rule path filter)",
					caller.FilePath, v.QueryID)
				continue
			}
			suppressAtCallSite(v, v.ModuleAttribution, caller)
		}
		kept = append(kept, *v)
	}
	return kept
}

// resolveLocation is the reporting policy for Terraform module findings. It
// runs after caller expansion, before filters, identity reduction or reports.
// A module finding must name an actual scanned repository caller. Attribution
// alone is not proof of reachability: an evaluated external root can also have
// a call chain. Files no repository call reaches have no reportable location.
//
// FileName and the detected ranges remain the module body, for fingerprints,
// provenance and fixes. ReportLocation is the resolved user-facing location;
// report writers must not derive it again or fall back to the module body.
func (r *findingRouting) resolveLocation(v *model.Vulnerability) (*model.FileMetadata, bool) {
	v.ReportLocation = nil
	attr := v.ModuleAttribution
	if attr == nil {
		return nil, v.ModuleCallChain == "" && !r.external(v.FileName)
	}
	location := attr.CallSite
	caller := r.callers[location.Filename]
	if caller == nil {
		return nil, false
	}
	location.LineStart = max(location.LineStart, 1)
	location.LineEnd = max(location.LineEnd, location.LineStart)
	location.ColumnStart = max(location.ColumnStart, 1)
	location.ColumnEnd = max(location.ColumnEnd, 1)
	if location.LineEnd == location.LineStart && location.ColumnEnd <= location.ColumnStart {
		location.ColumnEnd = location.ColumnStart + 1
	}
	v.ReportLocation = &location
	return caller, true
}

// expandModuleFindings clones findings from deduplicated OPA docs back to each
// extra caller, so every call-site gets its own fingerprint/file attribution.
func expandModuleFindings(
	vulns []model.Vulnerability, extras map[string][]extraCallerInfo, occurrences documentOccurrenceIndex,
) []model.Vulnerability {
	if len(extras) == 0 {
		return vulns
	}
	expanded := make([]model.Vulnerability, 0, len(vulns))
	for i := range vulns {
		expanded = append(expanded, vulns[i])
		for _, ex := range extras[vulns[i].FileID] {
			vCopy := vulns[i]
			vCopy.ModuleCallChain = ex.callChain
			vCopy.FileID = ex.docID
			vCopy.ModuleAttribution = moduleAttributionForResource(ex.attributions, &vCopy)
			if occurrences != nil {
				vCopy.ResourceOccurrences = callerOccurrences(vulns[i].ResourceOccurrences, occurrences[ex.docID])
			}
			expanded = append(expanded, vCopy)
		}
	}
	return expanded
}
