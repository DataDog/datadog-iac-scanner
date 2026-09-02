/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package runner

import (
	"bytes"
	"context"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/minified"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/google/uuid"
)

func (s *Service) resolverSink(
	ctx context.Context,
	filename, scanID string,
	openAPIResolveReferences bool,
	maxResolverDepth int) ([]string, error) {
	resFiles, kind, err := s.resolveOnly(ctx, filename)
	if kind == model.KindCOMMON {
		return []string{}, nil
	}
	if err != nil {
		s.logResolverResolveError(ctx, kind, filename, err)
		return []string{}, err
	}
	s.storeResolvedFiles(ctx, resFiles, kind, scanID, openAPIResolveReferences, maxResolverDepth)
	return resFiles.Excluded, nil
}

// resolveOnly renders a chart without parsing or storing it.
func (s *Service) resolveOnly(ctx context.Context, filename string) (model.ResolvedFiles, model.FileKind, error) {
	kind := s.Resolver.GetType(filename)
	if kind == model.KindCOMMON {
		return model.ResolvedFiles{}, kind, nil
	}
	resFiles, err := s.Resolver.Resolve(ctx, filename, kind)
	if err != nil {
		return model.ResolvedFiles{}, kind, err
	}
	return resFiles, kind, nil
}

// storeResolvedFiles parses and stores already-rendered files for this service.
func (s *Service) storeResolvedFiles(
	ctx context.Context,
	resFiles model.ResolvedFiles,
	kind model.FileKind,
	scanID string,
	openAPIResolveReferences bool,
	maxResolverDepth int) {
	contextLogger := logger.FromContext(ctx)
	sourceCache := make(map[string]*resolvedSourceData)
	for _, rfile := range resFiles.File {
		if isHelmJSONFile(kind, rfile.FileName) && s.Parser.Parsers.GetKind() != model.KindYAML {
			continue
		}
		s.Tracker.TrackFileFound(rfile.FileName)

		isMinified := minified.IsMinified(rfile.FileName, rfile.Content)
		documents, err := s.parseResolvedFile(
			ctx, rfile.FileName, rfile.Content, kind, openAPIResolveReferences, isMinified, maxResolverDepth)
		if err != nil {
			if documents.Kind == "break" {
				continue
			}
			// A Helm template may render to only comments when all range iterations are
			// conditionally skipped (e.g. a service disabled in prod). That's expected;
			// skip silently rather than logging a spurious error.
			if kind == model.KindHELM && isCommentOnlyContent(rfile.Content) {
				continue
			}
			contextLogger.Error().Err(err).Msgf("failed to parse file content '%s' with fileType '%s'", rfile.FileName, kind)
			continue
		}

		s.setResolvedLineMetadata(ctx, &documents, &rfile, sourceCache, kind,
			openAPIResolveReferences, isMinified, maxResolverDepth)

		cached := sourceCache[rfile.FileName]
		if len(documents.IgnoreLines) > 0 {
			sort.Ints(documents.IgnoreLines)
		}
		platform := s.classifyPlatform(ctx, kind, rfile.FileName, rfile.Content)
		ownedRenderedContent := ownedHelmRenderedContent(kind, rfile.IsCRD, rfile.Content)

		for docIdx, document := range documents.Docs {
			preparedDocument, prepareErr := prepareResolvedScanDocument(document, kind)
			err = prepareErr
			if err != nil {
				continue
			}

			lineInfoDocument := document
			if kind == model.KindHELM {
				lineInfoDocument = nil
			}
			file := model.FileMetadata{
				ID:                uuid.New().String(),
				ScanID:            scanID,
				Document:          preparedDocument,
				OriginalData:      cached.originalData,
				LineInfoDocument:  lineInfoDocument,
				Kind:              kind,
				FilePath:          rfile.FileName,
				HelmID:            rfile.SplitID,
				Commands:          cached.commands,
				IDInfo:            rfile.IDInfo,
				LinesIgnore:       documents.IgnoreLines,
				ResolvedFiles:     documents.ResolvedFiles,
				LinesOriginalData: cached.linesOriginalData,
				IsMinified:        documents.IsMinified,
				Platform:          platform,
			}
			if kind == model.KindHELM {
				file.SetLineInfoLoader(newHelmLineInfoLoader(
					s.Parser, &rfile, ownedRenderedContent, docIdx,
					openAPIResolveReferences, isMinified, maxResolverDepth))
			}
			s.saveToFile(ctx, &file)
		}
		s.Tracker.TrackFileParse(rfile.FileName)
		s.Tracker.TrackFileFoundCountLines(documents.CountLines)
		s.Tracker.TrackFileParseCountLines(documents.CountLines - len(documents.IgnoreLines))
		s.Tracker.TrackFileIgnoreCountLines(len(documents.IgnoreLines))

		if kind == model.KindTerraform {
			resourceCount := GetCountTerraformResources(rfile.Content)
			s.Tracker.TrackFileFoundCountResources(resourceCount)
		}
	}
}

func ownedHelmRenderedContent(kind model.FileKind, isCRD bool, content []byte) string {
	if kind != model.KindHELM || isCRD {
		return ""
	}
	return string(content)
}

// Helm line info is reparsed lazily, so its parsed tree is exclusively owned
// by the scan document and can be sanitized without a JSON round-trip.
func prepareResolvedScanDocument(
	document map[string]interface{},
	kind model.FileKind,
) (map[string]interface{}, error) {
	if kind == model.KindHELM {
		prepareScanDocumentRoot(document, kind)
		return document, nil
	}
	return prepareScanDocument(document, kind)
}

type resolvedSourceData struct {
	originalData      string
	linesOriginalData *[]string
	commands          model.CommentsCommands
	countLines        int
	ignoreLines       []int
	ignoreErr         error
	ignorePrepared    bool
}

func (s *Service) setResolvedLineMetadata(
	ctx context.Context,
	documents *parser.ParsedDocument,
	rfile *model.ResolvedHelm,
	sourceCache map[string]*resolvedSourceData,
	kind model.FileKind,
	openAPIResolveReferences, isMinified bool,
	maxResolverDepth int,
) {
	cached := sourceCache[rfile.FileName]
	if cached == nil {
		cached = newResolvedSourceData(ctx, s, rfile)
		sourceCache[rfile.FileName] = cached
	}
	if kind != model.KindHELM {
		documents.CountLines = cached.countLines + 1
		return
	}

	if rfile.IsCRD && !bytes.Contains(rfile.OriginalData, []byte("dd-iac-scan")) {
		documents.IgnoreLines = nil
		documents.CountLines = cached.countLines
		return
	}
	if !cached.ignorePrepared {
		cached.ignoreLines, cached.ignoreErr = s.getOriginalIgnoreLines(ctx,
			rfile.FileName, rfile.OriginalData,
			kind, openAPIResolveReferences, isMinified, maxResolverDepth)
		cached.ignorePrepared = true
	}
	if cached.ignoreErr == nil {
		documents.IgnoreLines = cached.ignoreLines
	} else {
		documents.IgnoreLines = filterHelmGeneratedLines(rfile.Content, documents.IgnoreLines)
	}
	documents.CountLines = cached.countLines
}

func newResolvedSourceData(
	ctx context.Context,
	s *Service,
	rfile *model.ResolvedHelm,
) *resolvedSourceData {
	originalData := string(rfile.OriginalData)
	return &resolvedSourceData{
		originalData:      originalData,
		linesOriginalData: utils.SplitLines(originalData),
		commands:          s.Parser.CommentsCommands(ctx, rfile.FileName, rfile.OriginalData),
		countLines:        bytes.Count(rfile.OriginalData, []byte{'\n'}),
	}
}

func (s *Service) parseResolvedFile(
	ctx context.Context,
	filename string,
	content []byte,
	kind model.FileKind,
	openAPIResolveReferences, isMinified bool,
	maxResolverDepth int,
) (parser.ParsedDocument, error) {
	if isHelmJSONFile(kind, filename) && s.Parser.Parsers.GetKind() == model.KindYAML {
		return s.Parser.ParseContent(
			ctx, filename, content, openAPIResolveReferences, isMinified, maxResolverDepth)
	}
	return s.Parser.Parse(
		ctx, filename, content, openAPIResolveReferences, isMinified, maxResolverDepth)
}

func isHelmJSONFile(kind model.FileKind, filename string) bool {
	return kind == model.KindHELM && strings.EqualFold(filepath.Ext(filename), ".json")
}

func newHelmLineInfoLoader(
	p *parser.Parser,
	rfile *model.ResolvedHelm,
	renderedContent string,
	renderedDocumentIndex int,
	openAPIResolveReferences bool,
	isMinified bool,
	maxResolverDepth int,
) func(context.Context, *model.FileMetadata) (map[string]interface{}, error) {
	if rfile.IsCRD {
		return newOriginalResolvedLineInfoLoader(
			p, rfile.FileName, rfile.SourceDocumentIndex,
			openAPIResolveReferences, isMinified, maxResolverDepth)
	}
	return newResolvedLineInfoLoader(
		p, rfile.FileName, renderedContent, renderedDocumentIndex,
		openAPIResolveReferences, isMinified, maxResolverDepth)
}

func newResolvedLineInfoLoader(
	p *parser.Parser,
	filename, renderedContent string,
	docIdx int,
	openAPIResolveReferences bool,
	isMinified bool,
	maxResolverDepth int,
) func(context.Context, *model.FileMetadata) (map[string]interface{}, error) {
	return newLineInfoLoaderWithReparser(filename, docIdx,
		func(ctx context.Context, _ *model.FileMetadata) (parser.ParsedDocument, error) {
			content := []byte(renderedContent)
			if isHelmJSONFile(model.KindHELM, filename) && p.Parsers.GetKind() == model.KindYAML {
				return p.ParseContent(
					ctx, filename, content, openAPIResolveReferences, isMinified, maxResolverDepth)
			}
			return p.Parse(
				ctx, filename, content, openAPIResolveReferences, isMinified, maxResolverDepth)
		})
}

func newOriginalResolvedLineInfoLoader(
	p *parser.Parser,
	filename string,
	sourceDocumentIndex int,
	openAPIResolveReferences bool,
	isMinified bool,
	maxResolverDepth int,
) func(context.Context, *model.FileMetadata) (map[string]interface{}, error) {
	return newLineInfoLoaderWithReparser(filename, sourceDocumentIndex,
		func(ctx context.Context, f *model.FileMetadata) (parser.ParsedDocument, error) {
			content := []byte(f.OriginalData)
			if isHelmJSONFile(model.KindHELM, filename) && p.Parsers.GetKind() == model.KindYAML {
				return p.ParseContent(
					ctx, filename, content, openAPIResolveReferences, isMinified, maxResolverDepth)
			}
			return p.Parse(
				ctx, filename, content, openAPIResolveReferences, isMinified, maxResolverDepth)
		})
}

// logResolverResolveError logs a Helm resolve/render failure as debug when it
// matches missing deploy-time values (expected at scan time), otherwise as error.
// Both paths fall back to raw-file scanning; only expected failures call
// recordFailedHelmChart, which suppresses subsequent parse-error noise for those files.
func (s *Service) logResolverResolveError(ctx context.Context, kind model.FileKind, filename string, err error) {
	contextLogger := logger.FromContext(ctx)
	if kind == model.KindHELM && isExpectedHelmRenderError(err) {
		s.recordFailedHelmChart(filename)
		contextLogger.Debug().Err(err).Msgf("helm chart '%s' could not be rendered with available values", filename)
		return
	}
	contextLogger.Error().Err(err).Msgf("failed to render file content '%s' with fileType '%s'", filename, kind)
}

// expectedHelmRenderErrorSignatures matches Go template execution errors caused
// by missing deploy-time values — the expected failure mode for charts that
// require values unavailable at scan time.
// "error calling required:" covers the Helm required helper, which exists
// exclusively to guard absent values.
// "error calling fail:" is intentionally excluded: fail is also used for real
// validation logic (e.g. unsupported kube version) that can trigger even when
// all values are present, so classifying it as expected would silence genuine
// chart errors.
var expectedHelmRenderErrorSignatures = []string{
	"nil pointer evaluating",
	"map has no entry for key",
	"can't evaluate field",
	"error calling required:",
}

func isExpectedHelmRenderError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, sig := range expectedHelmRenderErrorSignatures {
		if strings.Contains(msg, sig) {
			return true
		}
	}
	return false
}

// isCommentOnlyContent returns true when every non-blank line in content starts
// with '#', meaning the Helm renderer produced no real YAML document.
func isCommentOnlyContent(content []byte) bool {
	for _, line := range strings.Split(string(content), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			return false
		}
	}
	return true
}

var (
	helmIDLinePattern         = regexp.MustCompile(`(?m)^[ \t]*# KICS_HELM_ID_\d+:[^\r\n]*(?:\r?\n|$)`)
	helmTemplateActionPattern = regexp.MustCompile(`{{-\s*(.*?)\s*}}`)
)

func (s *Service) getOriginalIgnoreLines(ctx context.Context, filename string,
	originalFile []uint8,
	kind model.FileKind,
	openAPIResolveReferences, isMinified bool,
	maxResolverDepth int) (ignoreLines []int, err error) {
	refactor := helmIDLinePattern.ReplaceAll(originalFile, nil)
	refactor = helmTemplateActionPattern.ReplaceAll(refactor, nil)

	documentsOriginal, err := s.parseResolvedFile(
		ctx, filename, refactor, kind, openAPIResolveReferences, isMinified, maxResolverDepth)
	if err == nil {
		ignoreLines = documentsOriginal.IgnoreLines
	}
	return
}

// filterHelmGeneratedLines drops entries from ignoreLines whose corresponding
// line in content is a scanner-injected Helm header ("# Source: …" or
// "# KICS_HELM_ID_N:"). These headers are picked up by the YAML parser as
// regular head comments and can coincide with vulnerability.Line, causing false
// suppression. User-authored suppression comments are unaffected.
func filterHelmGeneratedLines(content []byte, ignoreLines []int) []int {
	lines := strings.Split(string(content), "\n")
	out := make([]int, 0, len(ignoreLines))
	for _, n := range ignoreLines {
		if n >= 1 && n <= len(lines) {
			trimmed := strings.TrimSpace(lines[n-1])
			if strings.HasPrefix(trimmed, "# Source:") ||
				strings.HasPrefix(trimmed, "# KICS_HELM_ID_") {
				continue
			}
		}
		out = append(out, n)
	}
	return out
}
