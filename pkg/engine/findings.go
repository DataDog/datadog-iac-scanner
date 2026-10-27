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
	"sync"

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
// A compacting set is given the rule's results last raised first, so the
// finding it keeps is the first one it is given. A result whose every
// identity is already kept can then be skipped before its line is detected
// (see supersedes).
//
// Routing runs before the identity is recorded. It gives a finding the call
// chain of each module caller it stands for, and two instances that share an
// identity can stand for different callers. Recording the identity first would
// drop the callers of every instance but the last.
type findingSet struct {
	out     []model.Vulnerability
	routing *findingRouting
	// kept holds the identities of the findings in out. Nil when the set is
	// not reducing by identity, so every finding is appended.
	kept   map[[sha256.Size]byte]struct{}
	keyBuf []byte
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
	// Routing changes only the call chain of what goes into the identity.
	id, lineFree := model.IdentityBeforeLine(v)
	for i := len(routed) - 1; i >= 0; i-- {
		if lineFree {
			s.keepChained(id, &routed[i])
		} else {
			s.keepKey(model.FindingIdentity(&routed[i]), &routed[i])
		}
	}
}

// keepChained records v unless id under v's call chain is already kept.
func (s *findingSet) keepChained(id model.ChainedIdentity, v *model.Vulnerability) {
	if s.has(id, v.ModuleCallChain) {
		return
	}
	s.kept[sha256.Sum256(s.keyBuf)] = struct{}{}
	s.out = append(s.out, *v)
}

func (s *findingSet) keepKey(key string, v *model.Vulnerability) {
	digest := sha256.Sum256([]byte(key))
	if _, ok := s.kept[digest]; ok {
		return
	}
	s.kept[digest] = struct{}{}
	s.out = append(s.out, *v)
}

// supersedes reports whether routing a result raised on file with identity id
// now would only produce identities this set already kept, so the result
// cannot change the report.
//
// It has to agree with findingRouting.route in that direction (see
// TestFindingSet_SupersedesMeansRouteKeepsNothingNew). The as-written
// identity is required only when routing can produce it: an external module
// file that is reported only through its calls does not.
func (s *findingSet) supersedes(id model.ChainedIdentity, file *model.FileMetadata, resourceType string) bool {
	if file == nil || len(s.kept) == 0 {
		return false
	}
	if !s.accounted(id, file.ID, resourceType, file.ModuleCallChain, len(file.ModuleAttributions) > 0) {
		return false
	}
	if s.routing == nil {
		return true
	}
	for _, ex := range s.routing.extras[file.ID] {
		if !s.accounted(id, ex.docID, resourceType, ex.callChain, len(ex.attributions) > 0) {
			return false
		}
	}
	return true
}

// accounted reports whether every identity routing can give a finding raised
// on document fileID and reported under chain is already kept.
func (s *findingSet) accounted(id model.ChainedIdentity, fileID, resourceType, chain string, attributionPossible bool) bool {
	var file *moduleFileCalls
	if s.routing != nil {
		file = s.routing.moduleFiles[fileID]
	}
	if file == nil || file.keptAsWritten(resourceType) {
		return s.has(id, chain)
	}
	// The calls are produced unless the line attributes the finding. The line
	// is not known yet, so every call has to be kept already.
	for i := range file.calls {
		if !s.has(id, file.calls[i].callChain) {
			return false
		}
	}
	// Kept as written, or attributed from the line. Without attributions the
	// as-written finding is not produced, and requiring it would never skip.
	if file.keepWritten || attributionPossible {
		return s.has(id, chain)
	}
	return true
}

func (s *findingSet) has(id model.ChainedIdentity, chain string) bool {
	s.keyBuf = id.AppendWithChain(s.keyBuf[:0], chain)
	_, ok := s.kept[sha256.Sum256(s.keyBuf)]
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
	// parts shares what the scan's findings hold equal.
	parts *findingParts
}

// findingParts shares, between the findings of one scan, the parts that are
// equal for many of them. The instances of a module block are findings on the
// same lines of the same file, so their block source, surrounding lines and
// narrowed module attribution are the same for every instance and for every
// rule flagging the same line. What it returns is shared and only read.
// A nil findingParts shares nothing.
type findingParts struct {
	mu           sync.Mutex
	sources      map[string]string
	lines        map[linesKey]*[]model.CodeLine
	attributions map[attributionKey]*model.ModuleAttribution
}

type linesKey struct {
	file string
	line int
}

// attributionKey holds what moduleAttributionForResource reads of a finding
// besides the attribution of its block, which it narrows.
type attributionKey struct {
	attribution   *model.ModuleAttribution
	line          int
	vulnerability model.ResourceLocation
	remediation   model.ResourceLocation
}

func newFindingParts() *findingParts {
	return &findingParts{
		sources:      make(map[string]string),
		lines:        make(map[linesKey]*[]model.CodeLine),
		attributions: make(map[attributionKey]*model.ModuleAttribution),
	}
}

// source returns s, or an equal block source seen before.
func (p *findingParts) source(s string) string {
	if p == nil || s == "" {
		return s
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if shared, ok := p.sources[s]; ok {
		return shared
	}
	p.sources[s] = s
	return s
}

// codeLines returns lines, or equal lines seen before around the same line of
// the same file.
func (p *findingParts) codeLines(file string, line int, lines *[]model.CodeLine) *[]model.CodeLine {
	if p == nil || lines == nil {
		return lines
	}
	key := linesKey{file: file, line: line}
	p.mu.Lock()
	defer p.mu.Unlock()
	if shared, ok := p.lines[key]; ok && slices.Equal(*shared, *lines) {
		return shared
	}
	p.lines[key] = lines
	return lines
}

// attribution returns moduleAttributionForResource(attrs, v), built once for
// the findings it reads the same of.
func (p *findingParts) attribution(attrs map[string]*model.ModuleAttribution, v *model.Vulnerability) *model.ModuleAttribution {
	base, ok := resourceAttribution(attrs, v)
	if p == nil || !ok {
		return moduleAttributionForResource(attrs, v)
	}
	key := attributionKey{attribution: base, line: v.Line, vulnerability: v.VulnerabilityLocation, remediation: v.RemediationLocation}
	p.mu.Lock()
	shared, ok := p.attributions[key]
	p.mu.Unlock()
	if ok {
		return shared
	}
	attr := moduleAttributionForResource(attrs, v)
	p.mu.Lock()
	p.attributions[key] = attr
	p.mu.Unlock()
	return attr
}

// parts returns what the set's findings share, or nil when it shares nothing.
func (s *findingSet) parts() *findingParts {
	if s == nil || s.routing == nil {
		return nil
	}
	return s.routing.parts
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
	return &findingRouting{extras: extras, moduleFiles: moduleFiles, callers: callers, parts: newFindingParts()}
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
	vulns = expandModuleFindings(vulns, r.extras, r.parts)
	vulns = attributeModuleFileFindings(vulns, r.moduleFiles)
	return c.filterAtCallSites(ctx, vulns, r.callers)
}
