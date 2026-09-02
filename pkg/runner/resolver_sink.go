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

		if kind == model.KindHELM {
			ignoreList, errorIL := s.getOriginalIgnoreLines(ctx,
				rfile.FileName, rfile.OriginalData,
				kind, openAPIResolveReferences, isMinified, maxResolverDepth)
			if errorIL == nil {
				documents.IgnoreLines = ignoreList

				// Need to ignore #KICS_HELM_ID Line
				documents.CountLines = bytes.Count(rfile.OriginalData, []byte{'\n'})
			} else {
				// Parsing the original template failed (e.g. unstrippable {{ }} expressions),
				// so IgnoreLines came from the rendered YAML. Strip scanner-injected header
				// lines (# Source: / # KICS_HELM_ID_N:) that would otherwise cause false
				// suppression when the Helm detector resolves vulnerability.Line to them.
				documents.IgnoreLines = filterHelmGeneratedLines(rfile.Content, documents.IgnoreLines)
			}
		} else {
			documents.CountLines = bytes.Count(rfile.OriginalData, []byte{'\n'}) + 1
		}

		fileCommands := s.Parser.CommentsCommands(ctx, rfile.FileName, rfile.OriginalData)
		originalData := string(rfile.OriginalData)
		// Computed once per rendered file and shared (same pointer) across every
		// document's FileMetadata below; see the equivalent comment in sink.go.
		linesOriginalData := utils.SplitLines(originalData)

		for _, document := range documents.Docs {
			_, err = json.Marshal(document)
			if err != nil {
				continue
			}

			if len(documents.IgnoreLines) > 0 {
				sort.Ints(documents.IgnoreLines)
			}

			file := model.FileMetadata{
				ID:           uuid.New().String(),
				ScanID:       scanID,
				Document:     PrepareScanDocument(ctx, document, kind),
				OriginalData: originalData,
				// Not lazily loaded here (unlike sink.go): OriginalData is the
				// unrendered Helm/OpenAPI source, but parsing (and thus a
				// reconstructed LineInfoDocument) needs rfile.Content, the
				// resolved/rendered text. Keeping it eager avoids the risk of
				// silently re-parsing the wrong content.
				LineInfoDocument:  document,
				Kind:              kind,
				FilePath:          rfile.FileName,
				HelmID:            rfile.SplitID,
				Commands:          fileCommands,
				IDInfo:            rfile.IDInfo,
				LinesIgnore:       documents.IgnoreLines,
				ResolvedFiles:     documents.ResolvedFiles,
				LinesOriginalData: linesOriginalData,
				IsMinified:        documents.IsMinified,
				Platform:          s.classifyPlatform(ctx, kind, rfile.FileName, rfile.Content),
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

func (s *Service) getOriginalIgnoreLines(ctx context.Context, filename string,
	originalFile []uint8,
	kind model.FileKind,
	openAPIResolveReferences, isMinified bool,
	maxResolverDepth int) (ignoreLines []int, err error) {
	refactor := regexp.MustCompile(`.*\n?.*KICS_HELM_ID.+\n`).ReplaceAll(originalFile, []uint8{})
	refactor = regexp.MustCompile(`{{-\s*(.*?)\s*}}`).ReplaceAll(refactor, []uint8{})

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
