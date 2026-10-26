/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/sync/singleflight"
)

// LineInfoParse reparses the file f is a document of, returning its documents
// and any values derived from the content while parsing it (see Derived).
type LineInfoParse func(ctx context.Context, f *FileMetadata) ([]Document, map[DerivedKey]any, error)

// LineInfoSource is one reparse of a file. Each of the file's documents, and
// each copy made of them, reads its line-info tree and its lines from it, so
// the file is parsed and split once per lease rather than once per document.
//
// The parse is kept only while a lease holds the source (see LeaseLineInfo).
// A load outside a lease parses and keeps nothing. Documents read while a
// lease holds the source share their trees, so a holder must treat them as
// read-only.
type LineInfoSource struct {
	mu      sync.Mutex
	parse   LineInfoParse
	docs    []Document
	err     error
	held    int
	pinned  bool
	lines   *linesLazyState
	derived map[DerivedKey]any
	flight  singleflight.Group
}

// DerivedKey names a value derived from a file's content, kept with its
// line-info parse. Keys from NewDerivedKey compare equal when their names do.
type DerivedKey struct{ name string }

// NewDerivedKey returns the key for name.
func NewDerivedKey(name string) DerivedKey { return DerivedKey{name} }

// HCLBodyKey is the *hclsyntax.Body a Terraform line-info reparse built from
// the file's own content, when that content was parsed unchanged.
var HCLBodyKey = NewDerivedKey("terraform.hclBody")

// NewLineInfoSource returns a source reading the documents parse returns.
func NewLineInfoSource(parse LineInfoParse) *LineInfoSource {
	return &LineInfoSource{parse: parse, lines: &linesLazyState{}}
}

// document returns document docIdx of the source's parse.
func (s *LineInfoSource) document(ctx context.Context, f *FileMetadata, docIdx int) (map[string]interface{}, error) {
	docs, err := s.load(ctx, f)
	if err != nil {
		return nil, err
	}
	if docIdx < 0 || docIdx >= len(docs) {
		return nil, fmt.Errorf("reparse of %s for line info produced %d documents, expected index %d",
			f.FilePath, len(docs), docIdx)
	}
	return docs[docIdx], nil
}

// load returns the source's parse. A failure is remembered and not retried,
// except a canceled parse, which the caller may retry. The file is parsed
// outside the mutex; concurrent callers for the same file share one parse.
// The shared parse ignores cancellation so one caller's cancel cannot fail
// the others; a caller whose own ctx is canceled gets its ctx error.
func (s *LineInfoSource) load(ctx context.Context, f *FileMetadata) ([]Document, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.err != nil {
		err := s.err
		s.mu.Unlock()
		return nil, err
	}
	if s.docs != nil {
		docs := s.docs
		s.mu.Unlock()
		return docs, nil
	}
	s.mu.Unlock()

	type loaded struct {
		docs    []Document
		derived map[DerivedKey]any
	}
	v, err, _ := s.flight.Do("load", func() (any, error) {
		s.mu.Lock()
		if s.err != nil {
			err := s.err
			s.mu.Unlock()
			return nil, err
		}
		if s.docs != nil {
			docs := s.docs
			s.mu.Unlock()
			return loaded{docs: docs}, nil
		}
		s.mu.Unlock()

		docs, derived, err := s.parse(context.WithoutCancel(ctx), f)
		if err != nil {
			if !isCanceled(err) {
				s.mu.Lock()
				s.err = err
				s.mu.Unlock()
			}
			return nil, err
		}

		s.mu.Lock()
		defer s.mu.Unlock()
		if s.docs != nil {
			return loaded{docs: s.docs}, nil
		}
		if s.held > 0 {
			s.docs = docs
			s.keepDerived(derived)
		}
		return loaded{docs: docs, derived: derived}, nil
	})
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if err != nil {
		return nil, err
	}
	return v.(loaded).docs, nil
}

// keepDerived stores the values a reparse derived, keeping any value Derived
// already published for the same key. Callers hold s.mu.
func (s *LineInfoSource) keepDerived(derived map[DerivedKey]any) {
	for key, value := range derived {
		if s.derived == nil {
			s.derived = map[DerivedKey]any{}
		}
		if _, ok := s.derived[key]; ok {
			continue
		}
		s.derived[key] = value
	}
}

func isCanceled(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// Lease keeps the parse loaded until the returned lease is closed, so the
// documents read while it is held share one parse. With no lease held the
// parse is dropped. Safe on a nil receiver, for a file that has no source.
func (s *LineInfoSource) Lease() *LineInfoLease {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	s.held++
	s.mu.Unlock()
	return &LineInfoLease{source: s}
}

// Pin keeps the parse loaded for as long as the source lives. Idempotent,
// and safe on a nil receiver. Pinning holds the one shared parse, which every
// document of the file points into; it does not keep a separate tree per
// document. The trade-off is that the parse then lives until the source does.
func (s *LineInfoSource) Pin() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if !s.pinned {
		s.pinned = true
		s.held++
	}
	s.mu.Unlock()
}

// sharedLines is the line state the file's documents split and search.
func (s *LineInfoSource) sharedLines() *linesLazyState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lines
}

// releaseLines drops the source's reference to the file's line split. Each
// document drops its own in ReleasePostEvalData, so the split is freed once
// the last document of the file is released.
func (s *LineInfoSource) releaseLines() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.lines = &linesLazyState{}
	s.mu.Unlock()
}

func (s *LineInfoSource) release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.held > 0 {
		s.held--
	}
	if s.held == 0 {
		s.docs = nil
		s.derived = nil
	}
}

// Derived returns the value build derives from the file, built once and kept
// while a lease holds the file's source. build runs outside the source lock.
// A failure is not kept, and neither is a value built while no lease holds
// the source. Concurrent callers for the same key share one build.
func (f *FileMetadata) Derived(key DerivedKey, build func() (any, error)) (any, error) {
	s := f.lineInfoSource
	if s == nil {
		return build()
	}
	s.mu.Lock()
	if value, ok := s.derived[key]; ok {
		s.mu.Unlock()
		return value, nil
	}
	s.mu.Unlock()

	v, err, _ := s.flight.Do("derived:"+key.name, func() (any, error) {
		s.mu.Lock()
		if value, ok := s.derived[key]; ok {
			s.mu.Unlock()
			return value, nil
		}
		s.mu.Unlock()

		value, err := build()
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if existing, ok := s.derived[key]; ok {
			return existing, nil
		}
		if s.held == 0 {
			return value, nil
		}
		if s.derived == nil {
			s.derived = map[DerivedKey]any{}
		}
		s.derived[key] = value
		return value, nil
	})
	return v, err
}

// LineInfoLease is one claim on a LineInfoSource's parse.
type LineInfoLease struct {
	source *LineInfoSource
}

// Close releases the lease. Idempotent, and safe on a nil receiver.
func (l *LineInfoLease) Close() {
	if l == nil || l.source == nil {
		return
	}
	l.source.release()
	l.source = nil
}

// LineInfoLeases holds one lease on each distinct line-info source of a set
// of files, such as the documents of one file and their copies.
type LineInfoLeases struct {
	files  []*FileMetadata
	leases []*LineInfoLease
}

// LeaseLineInfoOf leases each distinct line-info source of files once.
func LeaseLineInfoOf(files []*FileMetadata) *LineInfoLeases {
	l := &LineInfoLeases{}
	seenFiles := map[*FileMetadata]struct{}{}
	seenSources := map[*LineInfoSource]struct{}{}
	for _, f := range files {
		if f == nil {
			continue
		}
		if _, ok := seenFiles[f]; ok {
			continue
		}
		seenFiles[f] = struct{}{}
		l.files = append(l.files, f)
		if f.lineInfoSource == nil {
			continue
		}
		if _, ok := seenSources[f.lineInfoSource]; ok {
			continue
		}
		seenSources[f.lineInfoSource] = struct{}{}
		l.leases = append(l.leases, f.lineInfoSource.Lease())
	}
	return l
}

// Close drops the files' line-info trees, then releases the leases, so a
// source's parse is dropped once no file still holds a tree from it.
// Idempotent.
func (l *LineInfoLeases) Close() {
	if l == nil {
		return
	}
	for _, f := range l.files {
		f.DiscardLineInfoDocument()
	}
	for _, lease := range l.leases {
		lease.Close()
	}
	l.files, l.leases = nil, nil
}
