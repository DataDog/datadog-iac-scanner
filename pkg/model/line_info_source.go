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
)

// LineInfoParse reparses the file f is a document of, returning its documents.
type LineInfoParse func(ctx context.Context, f *FileMetadata) ([]Document, error)

// LineInfoSource is one reparse of a file. Each of the file's documents, and
// each copy made of them, reads its line-info tree and its lines from it, so
// the file is parsed and split once per lease rather than once per document.
//
// The parse is kept only while a lease holds the source (see LeaseLineInfo).
// A load outside a lease parses and keeps nothing. Documents read while a
// lease holds the source share their trees, so a holder must treat them as
// read-only.
type LineInfoSource struct {
	mu     sync.Mutex
	parse  LineInfoParse
	docs   []Document
	err    error
	held   int
	pinned bool
	lines  *linesLazyState
}

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
// except a canceled parse, which the caller may retry.
func (s *LineInfoSource) load(ctx context.Context, f *FileMetadata) ([]Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	if s.docs != nil {
		return s.docs, nil
	}
	docs, err := s.parse(ctx, f)
	if err != nil {
		if !isCanceled(err) {
			s.err = err
		}
		return nil, err
	}
	if s.held > 0 {
		s.docs = docs
	}
	return docs, nil
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
	}
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
