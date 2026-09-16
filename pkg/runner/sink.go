/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"sort"

	"github.com/DataDog/datadog-iac-scanner/pkg/analyzer"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	iacparser "github.com/DataDog/datadog-iac-scanner/pkg/parser"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/jsonfilter/parser"
	"github.com/antlr4-go/antlr/v4"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

var (
	lines = map[model.FileKind][]string{
		"TF":     {"pattern"},
		"TFPLAN": {"pattern"},
		"JSON":   {"FilterPattern"},
		"YAML":   {"filter_pattern", "FilterPattern"},
	}
)

// redactErrorForLog renders err for logging with URL credentials stripped.
//
// Parse/render errors are produced by third-party libraries that routinely
// quote the offending fragment of the file being scanned: e.g. the Ansible INI
// parser reports `bad key=value pair supplied: postgres://user:pass@host/db`.
// Since scanned files belong to customer repositories, logging such an error
// verbatim copies whatever credentials it happens to embed into our logs. The
// message is still needed for triage, so redact the credentials rather than
// dropping the error, and log the result under the same field `.Err()` would
// have used so downstream log consumers keep working.
func redactErrorForLog(err error) string {
	if err == nil {
		return ""
	}
	return model.RedactURLCredentials(err.Error())
}

func (s *Service) sink(ctx context.Context, filename, scanID string,
	rc io.Reader, data []byte,
	openAPIResolveReferences bool,
	maxResolverDepth int) error {
	c, err := getContent(rc, data, s.MaxFileSize, filename)
	return s.sinkContent(ctx, filename, scanID, c, err, openAPIResolveReferences, maxResolverDepth)
}

// sinkContent parses already-read file content; used when one read feeds several parsers.
func (s *Service) sinkContent(ctx context.Context, filename, scanID string,
	c *Content, getErr error,
	openAPIResolveReferences bool,
	maxResolverDepth int) error {
	contextLogger := logger.FromContext(ctx)
	s.Tracker.TrackFileFound(filename)

	*c.Content = resolveCRLFFile(*c.Content)
	content := c.Content
	err := getErr

	s.Tracker.TrackFileFoundCountLines(c.CountLines)
	s.Tracker.TrackFileFoundCountResources(c.CountResources)

	if err != nil {
		return errors.Wrapf(err, "failed to get file content: %s", filename)
	}
	// LinesOriginalData is lazy (see FileMetadata.Lines): most files never produce
	// a finding, so the SplitLines copy is not retained for the whole scan.
	fileCommands := s.Parser.CommentsCommands(ctx, filename, *content)

	// Fast path: duplicate content already parsed and sanitized — reuse the shared
	// trees with a per-file top-level map and skip parsing. The interned key also
	// serves the slow path below (pure function of content).
	shareKey, shared := s.lookupSharedParse(*c.Content)
	if shared != nil {
		return s.sinkSharedParse(ctx, filename, scanID, shareKey, shared,
			fileCommands, c.IsMinified, openAPIResolveReferences, maxResolverDepth, *content)
	}

	documents, err := s.Parser.Parse(ctx, filename, *content, openAPIResolveReferences, c.IsMinified, maxResolverDepth)
	if err != nil {
		// Raw templates inside a failed chart are not valid YAML; parse failures there are expected.
		if s.isUnderFailedHelmChart(filename) {
			contextLogger.Debug().Str(zerolog.ErrorFieldName, redactErrorForLog(err)).
				Msgf("skipping unparseable raw Helm template: %s", filename)
		} else {
			contextLogger.Error().Str(zerolog.ErrorFieldName, redactErrorForLog(err)).
				Msgf("failed to parse file content: %s", filename)
		}
		return nil
	}

	linesResolved := 0
	for _, ref := range documents.ResolvedFiles {
		if ref.Path != filename {
			linesResolved += len(*ref.LinesContent)
		}
	}
	s.Tracker.TrackFileFoundCountLines(linesResolved)

	if len(documents.ResolvedFiles) > 0 {
		documents.IgnoreLines = model.GetIgnoreLines(&model.FileMetadata{
			FilePath:     filename,
			OriginalData: documents.Content,
			LinesIgnore:  documents.IgnoreLines,
		})
	}
	// The ignore-lines slice is shared by every document of this file; sort
	// it once here instead of once per document in sinkDocument.
	if len(documents.IgnoreLines) > 0 {
		sort.Ints(documents.IgnoreLines)
	}

	shareable := shareKey != "" && shareableParse(&documents)
	var sharedDocs []model.Document

	for docIdx := range documents.Docs {
		if doc := s.sinkDocument(ctx, filename, scanID, &documents, docIdx, shareable,
			c.IsMinified, openAPIResolveReferences, maxResolverDepth, *content, fileCommands); doc != nil {
			sharedDocs = append(sharedDocs, doc)
		}
	}
	if shareable && len(sharedDocs) == len(documents.Docs) {
		// Every document sanitized cleanly: cache the sanitized trees for later
		// files with identical content (top-level copies, children shared).
		s.storeSharedParse(shareKey, &documents, sharedDocs)
	}
	s.Tracker.TrackFileParse(filename)

	s.Tracker.TrackFileParseCountLines(documents.CountLines - len(documents.IgnoreLines))
	s.Tracker.TrackFileIgnoreCountLines(len(documents.IgnoreLines))

	return nil
}

// sinkDocument sanitizes, canonicalizes and registers one parsed document of
// a freshly parsed file, returning its top-level map for the shared-parse
// cache (nil when the document was skipped or the parse is not shareable).
func (s *Service) sinkDocument(
	ctx context.Context,
	filename, scanID string,
	documents *iacparser.ParsedDocument,
	docIdx int,
	shareable, isMinified, openAPIResolveReferences bool,
	maxResolverDepth int,
	content []byte,
	fileCommands model.CommentsCommands,
) model.Document {
	contextLogger := logger.FromContext(ctx)
	document := documents.Docs[docIdx]

	// Sanitize in place — safe because the tree is exclusively owned (line info is
	// lazily reparsed) — and reject cycles, as json.Marshal would.
	preparedDocument, err := sanitizeScanDocumentInPlace(document, documents.Kind)
	if err != nil {
		contextLogger.Err(err).Msgf("failed to sanitize document for file: %s", filename)
		return nil
	}

	if shareable {
		// Canonicalize structurally identical subtrees; the top-level map stays
		// per-file (Combine inserts id/file into it).
		preparedDocument = s.consTreeChildren(preparedDocument)
	}

	file := model.FileMetadata{
		ID:            uuid.New().String(),
		ScanID:        scanID,
		Document:      preparedDocument,
		OriginalData:  s.internContent(documents.Content),
		Kind:          documents.Kind,
		FilePath:      filename,
		Commands:      fileCommands,
		LinesIgnore:   documents.IgnoreLines,
		ResolvedFiles: documents.ResolvedFiles,
		IsMinified:    documents.IsMinified,
		Platform:      s.classifyPlatform(ctx, documents.Kind, filename, content),
	}
	file.SetLineInfoLoader(newLineInfoLoader(
		s.Parser, filename, docIdx, openAPIResolveReferences, isMinified, maxResolverDepth))
	// Lazy lines, as in sinkContent.
	file.SetLazyLines()

	s.saveToFile(ctx, &file)
	if !shareable {
		return nil
	}
	return preparedDocument
}

// sinkSharedParse emits FileMetadata for a shared-parse cache hit: shallow
// top-level copies, per-file id and loader, cached tracker counts.
func (s *Service) sinkSharedParse(
	ctx context.Context,
	filename, scanID, key string,
	shared *sharedParse,
	fileCommands model.CommentsCommands,
	isMinified, openAPIResolveReferences bool,
	maxResolverDepth int,
	content []byte,
) error {
	for docIdx, sharedDoc := range shared.docs {
		file := model.FileMetadata{
			ID:           uuid.New().String(),
			ScanID:       scanID,
			Document:     cloneDocumentTopLevel(sharedDoc),
			OriginalData: key,
			Kind:         shared.kind,
			FilePath:     filename,
			Commands:     fileCommands,
			LinesIgnore:  shared.ignoreLines,
			IsMinified:   shared.isMinified,
			Platform:     s.classifyPlatform(ctx, shared.kind, filename, content),
		}
		file.SetLineInfoLoader(newLineInfoLoader(
			s.Parser, filename, docIdx, openAPIResolveReferences, isMinified, maxResolverDepth))
		file.SetLazyLines()
		s.saveToFile(ctx, &file)
	}
	s.Tracker.TrackFileParse(filename)
	s.Tracker.TrackFileParseCountLines(shared.countLines - len(shared.ignoreLines))
	s.Tracker.TrackFileIgnoreCountLines(len(shared.ignoreLines))
	return nil
}

// classifyPlatform applies the analyzer path cache, then ClassifyParsedFile.
func (s *Service) classifyPlatform(ctx context.Context, kind model.FileKind, filename string, content []byte) string {
	if platform, ok := s.FilePlatform[filepath.ToSlash(filename)]; ok {
		return platform
	}
	return analyzer.ClassifyParsedFile(ctx, s.Parser.FS(), s.Platforms, kind, filename, content)
}

func resolveCRLFFile(fileContent []byte) []byte {
	return bytes.ReplaceAll(fileContent, []byte("\r\n"), []byte("\n"))
}

func resolveJSONFilter(jsonFilter string) string {
	is := antlr.NewInputStream(jsonFilter)

	// lexer build
	lexer := parser.NewJSONFilterLexer(is)
	lexer.RemoveErrorListeners()
	stream := antlr.NewCommonTokenStream(lexer, antlr.TokenDefaultChannel)
	errorListener := parser.NewCustomErrorListener()
	lexer.RemoveErrorListeners()
	lexer.AddErrorListener(errorListener)

	// parser build
	p := parser.NewJSONFilterParser(stream)
	p.RemoveErrorListeners()
	p.AddErrorListener(errorListener)
	p.BuildParseTrees = true
	tree := p.Awsjsonfilter()

	// parse
	visitor := parser.NewJSONFilterPrinterVisitor()
	if errorListener.HasErrors() {
		return jsonFilter
	}

	parsed := visitor.VisitAll(tree)

	parsedByte, err := json.Marshal(parsed)
	if err != nil {
		return jsonFilter
	}

	return string(parsedByte)
}
