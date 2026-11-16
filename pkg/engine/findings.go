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
	out := s.out
	s.out, s.kept, s.keyBuf = nil, nil, nil
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
	// external reports whether a path is an external module file, reported
	// only through the calls that reach it. It may be nil.
	external func(string) bool
}

// newFindingRouting indexes the caller files once for the whole scan. The
// rules route concurrently, so the index is built before any of them run.
func newFindingRouting(
	extras map[string][]extraCallerInfo, moduleFiles map[string]*moduleFileCalls,
	files model.FileMetadatas, repoPath string, external func(string) bool,
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
	return &findingRouting{extras: extras, moduleFiles: moduleFiles, callers: callers, external: external}
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
	vulns = dropUnattributedExternalFindings(vulns, r.external)
	return c.filterAtCallSites(ctx, vulns, r.callers)
}
