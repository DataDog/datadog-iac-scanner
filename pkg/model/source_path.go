/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
)

// GitLabDialect identifies native GitLab pipeline documents.
const GitLabDialect = "gitlab"

// GitLabInputKey separates pipeline names from scanner document metadata.
const GitLabInputKey = GitLabDialect

// GitLabScriptsKey holds analysis of pipeline-global scripts outside job names.
const GitLabScriptsKey = "gitlab_scripts"

// PathSegment addresses exactly one object key or array index. Numeric-looking
// keys remain keys; they are never interpreted as array indexes.
type PathSegment struct {
	Key     string
	Index   int
	IsIndex bool
}

// SourcePath addresses written syntax within a finding's source document.
// Normalized or generated semantic views require an explicit source adapter.
type SourcePath []PathSegment

// DisplayKey formats an unambiguous source location for display only.
// It is never parsed back for source lookup or used as a finding identity.
func (path SourcePath) DisplayKey() string {
	parts := make([]interface{}, 0, len(path))
	for _, segment := range path {
		if segment.IsIndex {
			parts = append(parts, segment.Index)
		} else {
			parts = append(parts, segment.Key)
		}
	}
	raw, _ := json.Marshal(parts) // Only strings and integers are encoded.
	return string(raw)
}

// SourceSnapshot is one immutable source file shared by its compiled documents.
// Directives are decoded once, independently of compilation and interpolation.
type SourceSnapshot struct {
	Path         string
	Content      string
	IgnoreLines  []int
	declarations map[int][]int
	documentEnds map[int]int
	lastDocument int
	hasDocument  bool
	linesOnce    sync.Once
	lines        *[]string
}

// Lines returns the source's shared immutable line snapshot.
func (s *SourceSnapshot) Lines() *[]string {
	s.linesOnce.Do(func() { s.lines = utils.SplitLines(s.Content) })
	return s.lines
}

// RecordDeclarations records the raw top-level boundaries before compilation.
// It is called only while constructing this otherwise immutable snapshot.
func (s *SourceSnapshot) RecordDeclarations(index int, starts []int) {
	if s.declarations == nil {
		s.declarations = make(map[int][]int)
		s.documentEnds = make(map[int]int)
	}
	if _, seen := s.declarations[index]; seen {
		return
	}
	if s.hasDocument && len(starts) > 0 {
		s.documentEnds[s.lastDocument] = starts[0] - 1
	}
	s.declarations[index] = starts
	s.lastDocument = index
	s.hasDocument = true
}

// DeclarationSpan finds the original declaration containing a contributing
// field, including interpolated job names, without decoding the source again.
func (s *SourceSnapshot) DeclarationSpan(document, line int) (start, end int) {
	starts := s.declarations[document]
	index := sort.Search(len(starts), func(i int) bool { return starts[i] > line }) - 1
	if index < 0 {
		return line, line
	}
	start = starts[index]
	lines := s.Lines()
	end = len(*lines)
	if known := s.documentEnds[document]; known > 0 {
		end = known
	}
	if index+1 < len(starts) {
		end = starts[index+1] - 1
	}
	for end > start {
		raw := (*lines)[end-1]
		text := strings.TrimSpace(raw)
		if text != "" && !strings.HasPrefix(text, "#") && !sourceDocumentBoundary(raw) {
			break
		}
		end--
	}
	return start, end
}

// Stream markers must begin at column one; indented marker-like content can
// belong to a block scalar and remains part of the declaration.
func sourceDocumentBoundary(line string) bool {
	if len(line) < 3 || (line[:3] != "---" && line[:3] != "...") {
		return false
	}
	return len(line) == 3 || line[3] == ' ' || line[3] == '\t'
}

// SourcePosition is a trusted compiler coordinate, separate from rule input.
type SourcePosition struct {
	Snapshot      *SourceSnapshot
	DocumentIndex int
	Line          int
}

// SourceRange maps a flattened list interval to one alias/reference use site.
type SourceRange struct {
	Start, End int
	Position   SourcePosition
}

// LineOverlay keeps source ownership and positions separate from shared values.
// A nonzero default overrides inherited positions; children retain exceptions.
type LineOverlay struct {
	// InheritedDefault contributes an effective job field, but does not make
	// its global declaration a job declaration for source-path filtering.
	InheritedDefault bool
	Partial          bool
	Line             int
	Snapshot         *SourceSnapshot
	DocumentIndex    int
	Children         map[string]*LineOverlay
	Ranges           []SourceRange
}

// Position returns this node's default source coordinate.
func (o *LineOverlay) Position() SourcePosition {
	if o == nil {
		return SourcePosition{}
	}
	return SourcePosition{Snapshot: o.Snapshot, DocumentIndex: o.DocumentIndex, Line: o.Line}
}

// LookupSource finds the contributing source or inheritance/reference use site.
func (o *LineOverlay) LookupSource(path []string) SourcePosition {
	if o == nil {
		return SourcePosition{}
	}
	for _, key := range path {
		if index, err := strconv.Atoi(key); err == nil {
			// Ranges precede children because a reference relocates its whole value.
			indexRange := sort.Search(len(o.Ranges), func(i int) bool { return o.Ranges[i].End > index })
			if indexRange < len(o.Ranges) && o.Ranges[indexRange].Start <= index {
				return o.Ranges[indexRange].Position
			}
		}
		next, exists := o.Children[key]
		if !exists || next == nil {
			return o.Position()
		}
		o = next
	}
	return o.Position()
}

// Lookup returns a compiler/use-site line, or zero if written lookup applies.
func (o *LineOverlay) Lookup(path []string) int { return o.LookupSource(path).Line }

// Components preserves literal keys while addressing a compiler source tree.
func (path SourcePath) Components() []string {
	parts := make([]string, len(path))
	for i, segment := range path {
		parts[i] = segment.Key
		if segment.IsIndex {
			parts[i] = strconv.Itoa(segment.Index)
		}
	}
	return parts
}

// FindingSourceAt selects immutable source metadata for a compiled field.
func (f *FileMetadata) FindingSourceAt(path []string) (*FileMetadata, int, bool) {
	if len(f.SourceFiles) == 0 {
		return f, 0, false
	}
	position := f.LineOverlay.LookupSource(path)
	prototype := f.SourceFiles[position.Snapshot]
	if prototype == nil || position.Line < 1 {
		return f, 0, false
	}
	source := *prototype
	source.ID = f.ID
	source.ScanID = f.ScanID
	source.DocumentKey = f.DocumentKey
	source.Kind = f.Kind
	source.Platform = f.Platform
	source.SourceDocumentIndex = position.DocumentIndex
	source.SourceDocumentIndexKnown = true
	return &source, position.Line, true
}
