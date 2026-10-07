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
	"sync/atomic"

	"github.com/DataDog/datadog-iac-scanner/pkg/helmmarker"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/minified"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
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
	for i := range resFiles.File {
		rfile := &resFiles.File[i]
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
			contextLogger.Error().Str(zerolog.ErrorFieldName, redactErrorForLog(err)).
				Msgf("failed to parse file content '%s' with fileType '%s'", rfile.FileName, kind)
			continue
		}

		s.setResolvedLineMetadata(ctx, &documents, rfile, sourceCache, kind,
			openAPIResolveReferences, isMinified, maxResolverDepth)

		cached := sourceCache[rfile.FileName]
		if len(documents.IgnoreLines) > 0 {
			sort.Ints(documents.IgnoreLines)
		}
		platform := s.classifyPlatform(ctx, kind, rfile.FileName, rfile.Content)
		ownedRenderedContent := ownedHelmRenderedContent(kind, rfile.IsCRD, rfile.Content)

		for docIdx, document := range documents.Docs {
			preparedDocument, prepareErr := prepareResolvedScanDocument(document, kind)
			if prepareErr != nil {
				contextLogger.Error().Str(zerolog.ErrorFieldName, redactErrorForLog(prepareErr)).
					Msgf("failed to prepare scan document '%s' with fileType '%s'", rfile.FileName, kind)
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
				HelmAttribution:   model.NewHelmAttribution(rfile.HelmInvocations, ownedRenderedContent),
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
					s.Parser, rfile, ownedRenderedContent, docIdx,
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

// logResolverResolveError records a failed Helm chart and logs the failure.
// Every failed chart falls back to raw-file scanning, and its raw templates are
// never valid YAML, so recordFailedHelmChart silences their parse errors
// whatever the render failure was.
func (s *Service) logResolverResolveError(ctx context.Context, kind model.FileKind, filename string, err error) {
	if kind == model.KindHELM {
		s.recordFailedHelmChart(filename)
	}
	logResolveError(ctx, kind, filename, err)
}

// logResolveError logs a resolve/render failure as debug when it is expected
// at scan time (see classifyHelmRenderError), otherwise as error.
func logResolveError(ctx context.Context, kind model.FileKind, filename string, err error) {
	contextLogger := logger.FromContext(ctx)
	if kind == model.KindHELM && isExpectedHelmRenderError(err) {
		contextLogger.Debug().Str(zerolog.ErrorFieldName, redactErrorForLog(err)).
			Msgf("helm chart '%s' could not be rendered with available values", filename)
		return
	}
	// Render errors quote the offending template/values fragment, so they are
	// redacted for the same reason parse errors are — see redactErrorForLog.
	contextLogger.Error().Str(zerolog.ErrorFieldName, redactErrorForLog(err)).
		Msgf("failed to render file content '%s' with fileType '%s'", filename, kind)
}

// helmRenderFailure is why a chart could not be rendered at scan time.
type helmRenderFailure int

const (
	// helmRenderUnexpected is a chart error worth reporting on its own.
	helmRenderUnexpected helmRenderFailure = iota
	// helmRenderDeployTimeValue is a value only supplied at deploy time: the
	// chart is rendered at scan time with its default values alone.
	helmRenderDeployTimeValue
	// helmRenderMissingHelper is a named template that lives in a parent or
	// library chart outside the scan.
	helmRenderMissingHelper
)

// deployTimeValueSignatures are Go template errors on absent values, and
// "execution error at (", the shape Helm rewrites required and fail to before
// the error reaches the scan. Type errors such as "wrong type for value" or
// "range can't iterate over" are not here: they are as often a chart bug.
var deployTimeValueSignatures = []string{
	"nil pointer evaluating",
	"map has no entry for key",
	"can't evaluate field",
	"execution error at (",
	"interface conversion: interface {} is nil",
	"index of untyped nil",
	"len of nil pointer",
	"on zero Value",
	"invalid value; expected ",
}

// nilValueOfWrongType is the type error Go templates raise for a key that is
// present but empty (`tag:`): the value is a nil interface, a value left for
// deploy time rather than one of the wrong type.
var nilValueOfWrongType = regexp.MustCompile(`wrong type for value; expected [^;]+; got interface \{\}`)

// A template is reported as `template "x" not defined`, a misspelled function
// as `function "x" not defined`: only the first one is a missing helper.
var (
	undefinedHelmTemplate  = regexp.MustCompile(`template "[^"]*" not defined`)
	unassociatedHelmHelper = `" associated with template`
)

func classifyHelmRenderError(err error) helmRenderFailure {
	if err == nil {
		return helmRenderUnexpected
	}
	msg := err.Error()
	switch {
	case containsAny(msg, deployTimeValueSignatures) || nilValueOfWrongType.MatchString(msg):
		return helmRenderDeployTimeValue
	case strings.Contains(msg, unassociatedHelmHelper) || undefinedHelmTemplate.MatchString(msg):
		return helmRenderMissingHelper
	}
	return helmRenderUnexpected
}

func containsAny(msg string, signatures []string) bool {
	for _, sig := range signatures {
		if strings.Contains(msg, sig) {
			return true
		}
	}
	return false
}

func isExpectedHelmRenderError(err error) bool {
	return classifyHelmRenderError(err) != helmRenderUnexpected
}

// helmRenderNeedsNoFiles reports a render failure that re-pushing the chart
// cannot fix because it comes from a missing deploy-time value. A missing
// helper may come from a chart the IDE has not pushed yet, so it does not.
func helmRenderNeedsNoFiles(err error) bool {
	return classifyHelmRenderError(err) == helmRenderDeployTimeValue
}

// unrenderedHelmCharts counts the charts of a scan that failed to render for an
// expected reason. Each is only logged at debug, so the count is reported once
// at warn: those charts were scanned from their raw templates only.
type unrenderedHelmCharts struct {
	deployTimeValue, missingHelper atomic.Int64
}

func (u *unrenderedHelmCharts) record(err error) {
	switch classifyHelmRenderError(err) {
	case helmRenderDeployTimeValue:
		u.deployTimeValue.Add(1)
	case helmRenderMissingHelper:
		u.missingHelper.Add(1)
	case helmRenderUnexpected:
	}
}

func (u *unrenderedHelmCharts) log(ctx context.Context) {
	values, helpers := u.deployTimeValue.Load(), u.missingHelper.Load()
	if values+helpers == 0 {
		return
	}
	contextLogger := logger.FromContext(ctx)
	contextLogger.Warn().Msgf(
		"%d Helm charts could not be rendered and only their raw files were scanned "+
			"(deploy-time values: %d, helpers from charts outside the scan: %d); "+
			"run with --log-level debug to list them", values+helpers, values, helpers)
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

func (s *Service) getOriginalIgnoreLines(ctx context.Context, filename string,
	originalFile []uint8,
	kind model.FileKind,
	openAPIResolveReferences, isMinified bool,
	maxResolverDepth int) (ignoreLines []int, err error) {
	refactor := helmmarker.Blank(helmmarker.RemoveIDLines(originalFile))

	documentsOriginal, err := s.parseResolvedFile(
		ctx, filename, refactor, kind, openAPIResolveReferences, isMinified, maxResolverDepth)
	if err == nil {
		ignoreLines = documentsOriginal.IgnoreLines
	}
	return
}

// filterHelmGeneratedLines drops entries from ignoreLines whose corresponding
// line in content is a scanner-injected Helm header ("# Source: …" or
// "# KICS_HELM_ID_T_N:"). These headers are picked up by the YAML parser as
// regular head comments and can coincide with vulnerability.Line, causing false
// suppression. User-authored suppression comments are unaffected.
func filterHelmGeneratedLines(content []byte, ignoreLines []int) []int {
	lines := strings.Split(string(content), "\n")
	out := make([]int, 0, len(ignoreLines))
	for _, n := range ignoreLines {
		if n >= 1 && n <= len(lines) {
			trimmed := strings.TrimSpace(lines[n-1])
			if strings.HasPrefix(trimmed, "# Source:") ||
				strings.HasPrefix(trimmed, helmmarker.IDPrefix) {
				continue
			}
		}
		out = append(out, n)
	}
	return out
}
