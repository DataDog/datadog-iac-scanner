/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"cmp"
	"context"
	"crypto/sha256"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// findingSet collects the findings of one rule as they are decoded and
// routed, optionally keeping one per identity.
//
// A compacting set keeps the first finding of each identity in
// model.CompareFindings order (see Inspector.SetCompactFindingsAtDecode).
// A result that cannot come before what is kept can be skipped before its
// line is detected (see supersedes).
//
// Routing runs before the identity is recorded. Two instances that share an
// identity can stand for different callers, and recording the identity first
// would drop the callers of every instance but the first.
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
	resourceType string
	// chained is the identity of a finding identified by its file, resource
	// and module call chain.
	chained model.ChainedIdentity
	// docID, fileName and searchKey are where the result was raised, set by
	// supersedes. The reported fields are known before the line is, and
	// CompareFindings orders on them before remediation.
	docID, fileName, searchKey                          string
	queryID, queryName, platform, severity, description string
	remediation, remediationType                        string
}

// newResultIdentity is the identity of the findings of a result raised on file,
// before its line is detected. known is false when the identity includes the
// line.
func newResultIdentity(
	file *model.FileMetadata, platform, resourceType, resourceName, queryID, legacyQueryID string,
) (r resultIdentity, known bool) {
	r = resultIdentity{resourceType: resourceType, queryID: queryID}
	r.chained, known = model.ChainedIdentityFor(file.FilePath, platform, resourceType, resourceName, queryID, legacyQueryID)
	return r, known
}

// supersedes reports whether routing result r, raised on file at searchKey,
// would only produce identities this set already kept on a finding that comes
// first, so the result cannot change the report. Its line is not known yet,
// so a finding kept on the same file comes first only when it was raised at
// the same search key on a document built from the same written file: the
// instances of one block detect the same location there. Their remediation
// can still differ, and that is part of what the report keeps.
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
	if !s.accounted(r, file.ID, file.ModuleCallChain, len(file.ModuleAttributions) > 0) {
		return false
	}
	if s.routing == nil {
		return true
	}
	for _, ex := range s.routing.extras[file.ID] {
		if !s.accounted(r, ex.docID, ex.callChain, len(ex.attributions) > 0) {
			return false
		}
	}
	return true
}

// accounted reports whether every identity routing can give a finding raised
// on document fileID and reported under chain is already kept.
func (s *findingSet) accounted(r *resultIdentity, fileID, chain string, attributionPossible bool) bool {
	var file *moduleFileCalls
	if s.routing != nil {
		file = s.routing.moduleFiles[fileID]
	}
	if file == nil || file.keptAsWritten(r.resourceType) {
		return s.hasRoute(r, chain)
	}
	// The calls are produced unless the line attributes the finding. The line
	// is not known yet, so every call has to be kept already.
	for i := range file.calls {
		if !s.hasRoute(r, file.calls[i].callChain) {
			return false
		}
	}
	// Kept as written, or attributed from the line. Without attributions the
	// as-written finding is not produced, and requiring it would never skip.
	if file.keepWritten || attributionPossible {
		return s.hasRoute(r, chain)
	}
	return true
}

// hasRoute reports whether the finding of r routed under chain is already
// kept on a finding that comes first.
func (s *findingSet) hasRoute(r *resultIdentity, chain string) bool {
	s.keyBuf = r.chained.AppendWithChain(s.keyBuf[:0], chain)
	i, ok := s.kept[sha256.Sum256(s.keyBuf)]
	if !ok {
		return false
	}
	kept := &s.out[i]
	if kept.FileName != r.fileName {
		return kept.FileName < r.fileName
	}
	if kept.SearchKey != r.searchKey || writtenFileID(s.detectedOn[i]) != writtenFileID(r.docID) {
		return false
	}
	// These fields sort before remediation. Skipping without them keeps a
	// result the report would have ordered first. QueryID is compared before
	// QueryName as in CompareFindings: two results can share a legacy identity
	// and still differ on the reported id.
	if c := cmp.Or(
		cmp.Compare(kept.QueryID, r.queryID),
		cmp.Compare(kept.QueryName, r.queryName),
		cmp.Compare(kept.Platform, r.platform),
		cmp.Compare(string(kept.Severity), r.severity),
		cmp.Compare(kept.Description, r.description),
		cmp.Compare(kept.Remediation, r.remediation),
	); c != 0 {
		return c < 0
	}
	return cmp.Compare(kept.RemediationType, r.remediationType) <= 0
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
