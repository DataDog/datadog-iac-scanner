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
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/jsonfilter/parser"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/antlr4-go/antlr/v4"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

var (
	lines = map[model.FileKind][]string{
		"TF":   {"pattern"},
		"JSON": {"FilterPattern"},
		"YAML": {"filter_pattern", "FilterPattern"},
	}
)

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
	documents, err := s.Parser.Parse(ctx, filename, *content, openAPIResolveReferences, c.IsMinified, maxResolverDepth)
	if err != nil {
		// Raw templates inside a failed chart are not valid YAML; parse failures there are expected.
		if s.isUnderFailedHelmChart(filename) {
			contextLogger.Debug().Err(err).Msgf("skipping unparseable raw Helm template: %s", filename)
		} else {
			contextLogger.Error().Err(err).Msgf("failed to parse file content: %s", filename)
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

	fileCommands := s.Parser.CommentsCommands(ctx, filename, *content)

	// Computed once per file and shared (same pointer) across every document's
	// FileMetadata below: documents.Content is identical for every document of
	// a file, so splitting it inside the loop re-split (and separately
	// retained) the whole file once per document — a multi-document YAML file
	// (e.g. "---"-separated Kubernetes manifests) with N documents paid N
	// times the memory and CPU for the exact same line slice.
	linesOriginalData := utils.SplitLines(documents.Content)

	for docIdx, document := range documents.Docs {
		// Deep-copy + sanitize the document with a single marshal. A marshal
		// failure means the document can't be scanned, so skip it (preserving
		// the previous skip-on-unmarshalable-document behavior).
		preparedDocument, err := prepareScanDocument(document, documents.Kind)
		if err != nil {
			contextLogger.Err(err).Msgf("failed to marshal document for file: %s", filename)
			continue
		}

		if len(documents.IgnoreLines) > 0 {
			sort.Ints(documents.IgnoreLines)
		}

		file := model.FileMetadata{
			ID:                uuid.New().String(),
			ScanID:            scanID,
			Document:          preparedDocument,
			OriginalData:      documents.Content,
			Kind:              documents.Kind,
			FilePath:          filename,
			Commands:          fileCommands,
			LinesIgnore:       documents.IgnoreLines,
			ResolvedFiles:     documents.ResolvedFiles,
			LinesOriginalData: linesOriginalData,
			IsMinified:        documents.IsMinified,
			Platform:          s.classifyPlatform(ctx, documents.Kind, filename, *content),
		}
		file.SetLineInfoLoader(newLineInfoLoader(
			s.Parser, filename, docIdx, openAPIResolveReferences, c.IsMinified, maxResolverDepth))

		s.saveToFile(ctx, &file)
	}
	s.Tracker.TrackFileParse(filename)

	s.Tracker.TrackFileParseCountLines(documents.CountLines - len(documents.IgnoreLines))
	s.Tracker.TrackFileIgnoreCountLines(len(documents.IgnoreLines))

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
