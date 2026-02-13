/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package kics

import (
	"context"
	"encoding/json"
	"io"
	"regexp"
	"sort"

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
	contextLogger := logger.FromContext(ctx)
	s.Tracker.TrackFileFound(filename)

	c, err := getContent(rc, data, s.MaxFileSize, filename)

	*c.Content = resolveCRLFFile(*c.Content)
	content := c.Content

	s.Tracker.TrackFileFoundCountLines(c.CountLines)
	s.Tracker.TrackFileFoundCountResources(c.CountResources)

	if err != nil {
		return errors.Wrapf(err, "failed to get file content: %s", filename)
	}
	documents, err := s.Parser.Parse(ctx, filename, *content, openAPIResolveReferences, c.IsMinified, maxResolverDepth)
	if err != nil {
		contextLogger.Err(err).Msgf("failed to parse file content: %s", filename)
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

	for _, document := range documents.Docs {
		_, err = json.Marshal(document)
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
			Document:          PrepareScanDocument(ctx, document, documents.Kind),
			LineInfoDocument:  document,
			OriginalData:      documents.Content,
			Kind:              documents.Kind,
			FilePath:          filename,
			Commands:          fileCommands,
			LinesIgnore:       documents.IgnoreLines,
			ResolvedFiles:     documents.ResolvedFiles,
			LinesOriginalData: utils.SplitLines(documents.Content),
			IsMinified:        documents.IsMinified,
		}

		s.saveToFile(ctx, &file)
	}
	s.Tracker.TrackFileParse(filename)

	s.Tracker.TrackFileParseCountLines(documents.CountLines - len(documents.IgnoreLines))
	s.Tracker.TrackFileIgnoreCountLines(len(documents.IgnoreLines))

	return nil
}

func resolveCRLFFile(fileContent []byte) []byte {
	regex := regexp.MustCompile(`\r\n`)
	contentSTR := regex.ReplaceAllString(string(fileContent), "\n")
	return []byte(contentSTR)
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
