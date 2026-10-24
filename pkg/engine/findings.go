/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
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
// Routing runs before the identity is recorded. It gives a finding the call
// chain of each module caller it stands for, and two instances that share an
// identity can stand for different callers. Recording the identity first would
// drop the callers of every instance but the last.
type findingSet struct {
	out []model.Vulnerability
	// at is the position in out of the finding kept for an identity. Nil when
	// the set is not reducing by identity, so add appends unconditionally.
	at map[string]int
}

// newFindingSet starts a set that reduces findings to one per identity when
// compact is true, or keeps every finding it is given when compact is false.
func newFindingSet(compact bool) *findingSet {
	if !compact {
		return &findingSet{}
	}
	return &findingSet{at: make(map[string]int)}
}

// addRouted routes v to the module callers it stands for and keeps the last
// finding of each identity that routing produced.
func (s *findingSet) addRouted(ctx context.Context, c *Inspector, routing *findingRouting, v *model.Vulnerability) {
	routed := routing.route(ctx, c, []model.Vulnerability{*v})
	for i := range routed {
		s.add(&routed[i])
	}
}

// add keeps v as the finding of its identity, replacing the one kept before
// it, when the set reduces by identity; otherwise it appends v unconditionally.
// Either way, findings are kept in the order the rule raised them.
func (s *findingSet) add(v *model.Vulnerability) {
	if s.at == nil {
		s.out = append(s.out, *v)
		return
	}
	key := model.FindingIdentity(v)
	if at, ok := s.at[key]; ok {
		s.out[at] = *v
		return
	}
	s.at[key] = len(s.out)
	s.out = append(s.out, *v)
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
		if f == nil || f.ModuleCallChain != "" {
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
