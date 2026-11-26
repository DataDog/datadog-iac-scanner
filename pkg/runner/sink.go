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
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/analyzer"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	iacparser "github.com/DataDog/datadog-iac-scanner/pkg/parser"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/jsonfilter/parser"
	yamlparser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/cicd/gitlab"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/antlr4-go/antlr/v4"
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

type compilationFailure struct {
	path, reason string
	err          error
}

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

// logParseFailure logs a file that could not be parsed. Raw templates of a
// failed Helm chart, template syntax outside a chart and deliberately invalid
// test fixtures are expected not to parse, so they stay at debug level.
func (s *Service) logParseFailure(ctx context.Context, filename, reason string, err error) {
	contextLogger := logger.FromContext(ctx)
	switch reason {
	case model.ParseFailureUnresolvedInclude:
		contextLogger.Warn().Msgf("conditional include unresolved; retained unconditional pipeline: %s", filename)
	case model.ParseFailureHelmRenderFailed:
		contextLogger.Debug().Str(zerolog.ErrorFieldName, redactErrorForLog(err)).
			Msgf("skipping unparseable raw Helm template: %s", filename)
	case model.ParseFailureTestFixture, model.ParseFailureTemplateSyntax:
		contextLogger.Debug().Str(zerolog.ErrorFieldName, redactErrorForLog(err)).
			Msgf("skipping unparseable templated or fixture file: %s", filename)
	default:
		contextLogger.Error().Str(zerolog.ErrorFieldName, redactErrorForLog(err)).
			Msgf("failed to parse file content: %s", filename)
	}
}

// parseFailureReason classifies a parse failure, for its log level and for
// the exporters, such as the inventory.
func (s *Service) parseFailureReason(filename string, content []byte, err error) string {
	switch {
	case errors.Is(err, gitlab.ErrInvalidPipeline):
		return model.ParseFailureInvalidPipeline
	case errors.Is(err, gitlab.ErrConditionalInclude):
		return model.ParseFailureUnresolvedInclude
	case errors.Is(err, gitlab.ErrInvalidInclude):
		return model.ParseFailureInvalidInclude
	case errors.Is(err, gitlab.ErrLimitExceeded):
		return model.ParseFailureResourceLimit
	case s.isUnderFailedHelmChart(filename):
		return model.ParseFailureHelmRenderFailed
	case utils.IsTestFixturePath(filename):
		return model.ParseFailureTestFixture
	case utils.HasYAMLBreakingTemplate(content):
		return model.ParseFailureTemplateSyntax
	default:
		return model.ParseFailureParseError
	}
}

// Compiled failures are published only if their invocation survives selection.
// Ordinary parse failures retain immediate tracking and logging.
func (s *Service) recordParseFailure(ctx context.Context, filename string, content []byte, err error) {
	reason := s.parseFailureReason(filename, content, err)
	if isGitLabCompilationError(err) {
		s.filesMu.Lock()
		s.pendingCompilationFailures = append(s.pendingCompilationFailures, compilationFailure{filename, reason, err})
		s.filesMu.Unlock()
		return
	}
	s.logParseFailure(ctx, filename, reason, err)
	if errors.Is(err, yamlparser.ErrNoDocuments) {
		s.Tracker.TrackFileEmpty(filename)
	} else {
		s.Tracker.TrackFileFailed(filename, reason)
	}
}

func isGitLabCompilationError(err error) bool {
	return errors.Is(err, gitlab.ErrInvalidInclude) || errors.Is(err, gitlab.ErrLimitExceeded) ||
		errors.Is(err, gitlab.ErrConditionalInclude) || errors.Is(err, gitlab.ErrInvalidPipeline)
}

// sinkContent parses already-read file content; used when one read feeds several parsers.
func (s *Service) sinkContent(ctx context.Context, filename, scanID string,
	c *Content, getErr error,
	openAPIResolveReferences bool,
	maxResolverDepth int) error {
	s.Tracker.TrackFileFound(filename)

	*c.Content = resolveCRLFFile(*c.Content)
	content := c.Content
	err := getErr

	s.Tracker.TrackFileFoundCountLines(c.CountLines)
	s.Tracker.TrackFileFoundCountResources(c.CountResources)

	if err != nil {
		return errors.Wrapf(err, "failed to get file content: %s", filename)
	}
	// Fast path: duplicate content already parsed and sanitized — reuse the shared
	// trees with a per-file top-level map and skip parsing.
	if shared := s.lookupSharedParse(*c.Content); shared != nil {
		fileCommands := s.Parser.CommentsCommands(ctx, filename, *content)
		return s.sinkSharedParse(ctx, filename, scanID, shared.content, shared,
			fileCommands, c.IsMinified, openAPIResolveReferences, maxResolverDepth, *content)
	}

	// Line info is rebuilt on demand (see SetLineInfoLoader below), so the
	// documents' line markers are never read.
	ctx = gitlab.WithDeferredMissingRequests(ctx, func(publish func()) {
		s.filesMu.Lock()
		defer s.filesMu.Unlock()
		if s.pendingCompilationRequests == nil {
			s.pendingCompilationRequests = make(map[string][]func())
		}
		root := filepath.Clean(filepath.FromSlash(filename))
		s.pendingCompilationRequests[root] = append(s.pendingCompilationRequests[root], publish)
	})
	documents, err := s.Parser.Parse(iacparser.WithLazyLineInfo(ctx), filename, *content,
		openAPIResolveReferences, c.IsMinified, maxResolverDepth)
	if err != nil {
		s.recordParseFailure(ctx, filename, *content, err)
		return nil
	}
	s.recordCompilationDiagnostics(ctx, filename, *content, documents.Sources)
	var fileCommands model.CommentsCommands
	if documents.Kind == model.KindTerraform {
		// Checkout placeholders carry only the target path. File directives,
		// like line detection, must use the resolved Terraform source.
		fileCommands = s.Parser.CommentsCommandsFromString(ctx, filename, documents.Content)
	} else {
		fileCommands = s.Parser.CommentsCommands(ctx, filename, *content)
	}

	linesResolved := 0
	for _, ref := range documents.ResolvedFiles {
		if ref.Path != filename {
			linesResolved += len(*ref.LinesContent)
		}
	}
	s.Tracker.TrackFileFoundCountLines(linesResolved)

	// The ignore-lines slice is shared by every document of this file; sort
	// it once here instead of once per document in sinkDocument.
	if len(documents.IgnoreLines) > 0 {
		sort.Ints(documents.IgnoreLines)
	}

	documents.Content = s.internContent(documents.Content)
	sourceFiles := s.compiledSourceFiles(ctx, filename, &documents, fileCommands)
	sanitize := documentSanitizer(&documents)
	shareable := len(*content) > 0 && shareableParse(&documents)
	var sharedDocs []model.Document

	for docIdx := range documents.Docs {
		if doc := s.sinkDocument(ctx, filename, scanID, &documents, docIdx, shareable,
			c.IsMinified, openAPIResolveReferences, maxResolverDepth, *content, fileCommands, sourceFiles, sanitize); doc != nil {
			sharedDocs = append(sharedDocs, doc)
		}
	}
	if shareable && len(sharedDocs) == len(documents.Docs) {
		// Every document sanitized cleanly: cache the sanitized trees for later
		// files with identical content (top-level copies, children shared).
		s.storeSharedParse(s.internContentBytes(*content), &documents, sharedDocs)
	}
	s.Tracker.TrackFileParse(filename)
	if documents.TerraformPlan {
		s.Tracker.TrackTerraformPlanParse(filename)
	}

	s.Tracker.TrackFileParseCountLines(documents.CountLines - len(documents.IgnoreLines))
	s.Tracker.TrackFileIgnoreCountLines(len(documents.IgnoreLines))

	return nil
}

func (s *Service) recordCompilationDiagnostics(ctx context.Context, filename string, content []byte, sources []model.ParsedSource) {
	for index := range sources {
		if sources[index].Incomplete {
			s.recordParseFailure(ctx, filename, content, gitlab.ErrConditionalInclude)
			return
		}
	}
}

// documentSanitizer shares normalization state for the full compiled DAG.
func documentSanitizer(documents *iacparser.ParsedDocument) func(map[string]interface{}, model.FileKind) (map[string]interface{}, error) {
	for index := range documents.Sources {
		if documents.Sources[index].Dialect == model.GitLabDialect {
			return newCompiledDocumentSanitizer(true)
		}
	}
	if len(documents.ResolvedFiles) > 0 || documents.SharedNodes {
		return newSharedScanDocumentSanitizer()
	}
	return sanitizeScanDocumentInPlace
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
	sourceFiles map[*model.SourceSnapshot]*model.FileMetadata,
	sanitize func(map[string]interface{}, model.FileKind) (map[string]interface{}, error),
) model.Document {
	contextLogger := logger.FromContext(ctx)
	document := documents.Docs[docIdx]

	// Sanitize in place — safe because the tree is exclusively owned (line info is
	// lazily reparsed) — and reject cycles, as json.Marshal would.
	preparedDocument, err := sanitize(document, documents.Kind)
	if err != nil {
		contextLogger.Err(err).Msgf("failed to sanitize document for file: %s", filename)
		return nil
	}

	if shareable {
		// Canonicalize structurally identical subtrees; the top-level map stays
		// per-file (Combine inserts id/file into it).
		preparedDocument = s.consTreeChildren(preparedDocument)
	} else if documents.Kind == model.KindTerraformPlan {
		// A plan repeats most of its values: resource_changes holds each
		// resource's before and after values (equal for a no-op) next to the
		// planned values, and the parser's metadata copies after_unknown.
		// Plans are never module-instantiated, so their trees can be shared
		// like those of shareable parses; the interner is the plan's own.
		preparedDocument = newTreeHashCons().consChildren(preparedDocument)
	}

	key := s.documentKey(filename, documents.Kind, docIdx)
	file := model.FileMetadata{
		SourceDocumentIndex: docIdx,

		DocumentKey:   key,
		ID:            key.ID(),
		ScanID:        scanID,
		Document:      preparedDocument,
		OriginalData:  documents.Content,
		Kind:          documents.Kind,
		FilePath:      filename,
		Commands:      fileCommands,
		LinesIgnore:   documents.IgnoreLines,
		ResolvedFiles: documents.ResolvedFiles,
		IsMinified:    documents.IsMinified,
		Platform:      s.classifyPlatform(ctx, documents.Kind, filename, content),
	}
	file.SetLineInfoLoader(newLineInfoLoader(
		s.Parser, filename, docIdx, openAPIResolveReferences, isMinified, maxResolverDepth, s.LineInfoPayload))
	if docIdx < len(documents.Sources) {
		source := documents.Sources[docIdx]
		file.FilePath = source.Path
		file.OriginalData = source.Content
		file.SourceDocumentIndex = source.DocumentIndex
		file.SourceDocumentIndexKnown = true
		file.LineOverlay = source.LineOverlay
		file.DocumentDialect = source.Dialect
		if source.GlobalScripts != nil {
			file.GlobalScripts, err = sanitize(source.GlobalScripts, documents.Kind)
			if err != nil {
				contextLogger.Err(err).Msgf("failed to sanitize global scripts for file: %s", filename)
				return nil
			}
		}
		file.SourceFiles = sourceFiles
		file.CompilationRoot = filename
		file.SourceDependencies = source.Dependencies
		if cached := sourceFiles[source.Snapshot]; cached != nil {
			file.OriginalData = cached.OriginalData
			file.LinesIgnore = cached.LinesIgnore
			file.Commands = cached.Commands
		}

		rootContent := documents.Content
		file.SetLineInfoLoader(newLineInfoLoaderWithReparser(filename, docIdx,
			func(ctx context.Context, _ *model.FileMetadata) (iacparser.ParsedDocument, error) {
				ctx = iacparser.WithLineInfoOnly(ctx)
				if s.LineInfoPayload {
					ctx = iacparser.WithLineInfoExport(ctx)
				}
				return s.Parser.Parse(ctx, filename, []byte(rootContent), openAPIResolveReferences, isMinified, maxResolverDepth)
			}))
	}

	file.SetLineInfoOptional()
	if documents.Kind == model.KindTerraformPlan {
		file.SetLineInfoRetention(s.planLineInfoRetention())
		if !s.LineInfoPayload {
			file.SetLineInfoSectionLoader(newLineInfoSectionLoader(s.Parser, filename))
		}
	}
	// Lazy lines, as in sinkContent.
	file.SetLazyLines()

	s.filterCompiledJobs(&file)
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
		docKey := s.documentKey(filename, shared.kind, docIdx)
		file := model.FileMetadata{
			SourceDocumentIndex: docIdx,

			DocumentKey:  docKey,
			ID:           docKey.ID(),
			ScanID:       scanID,
			Document:     cloneSharedParseDocument(sharedDoc, filename),
			OriginalData: key,
			Kind:         shared.kind,
			FilePath:     filename,
			Commands:     fileCommands,
			LinesIgnore:  shared.ignoreLines,
			IsMinified:   shared.isMinified,
			Platform:     s.classifyPlatform(ctx, shared.kind, filename, content),
		}
		file.SetLineInfoLoader(newLineInfoLoader(
			s.Parser, filename, docIdx, openAPIResolveReferences, isMinified, maxResolverDepth, s.LineInfoPayload))
		file.SetLineInfoOptional()
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
	// bytes.ReplaceAll copies even when there is nothing to replace.
	if !bytes.Contains(fileContent, []byte("\r\n")) {
		return fileContent
	}
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

// compiledSourceFiles builds directives once per immutable input snapshot.
func (s *Service) compiledSourceFiles(
	ctx context.Context, filename string, documents *iacparser.ParsedDocument, rootCommands model.CommentsCommands,
) map[*model.SourceSnapshot]*model.FileMetadata {
	if len(documents.Sources) == 0 {
		return nil
	}
	sources := documents.Sources[0].Snapshots
	files := make(map[*model.SourceSnapshot]*model.FileMetadata, len(sources))
	for _, snapshot := range sources {
		commands := rootCommands
		if snapshot.Path != filename {
			ext := filepath.Ext(snapshot.Path)
			yamlPath := snapshot.Path[:len(snapshot.Path)-len(ext)] + strings.ToLower(ext)
			commands = s.Parser.CommentsCommandsFromString(ctx, yamlPath, snapshot.Content)
		}
		excluded := s.RenderedFileFilter != nil && s.RenderedFileFilter.ExcludesAny(snapshot.Path)
		if s.SourceExcluded != nil && s.SourceExcluded(snapshot.Path) {
			excluded = true
		}
		files[snapshot] = &model.FileMetadata{FilePath: snapshot.Path, OriginalData: s.internContent(snapshot.Content),
			LinesOriginalData: snapshot.Lines(), LinesIgnore: snapshot.IgnoreLines, Commands: commands, SourceExcluded: excluded}
	}
	return files
}

// filterCompiledJobs keeps the effective pipeline together while removing jobs
// with no in-scope contributing declaration. A later excluded override cannot
// hide an earlier in-scope script; individual finding filters still apply.
func (s *Service) filterCompiledJobs(file *model.FileMetadata) {
	if len(file.SourceFiles) == 0 || file.LineOverlay == nil {
		return
	}
	var replacement *model.LineOverlay
	for key, value := range file.Document {
		if !gitlab.IsExecutableJob(key, value) {
			continue
		}
		position := file.LineOverlay.LookupSource([]string{key})
		source := file.SourceFiles[position.Snapshot]
		if source == nil || !source.SourceExcluded {
			continue
		}
		candidate := inScopeJobSource(file, file.LineOverlay.Children[key])
		if candidate.Snapshot == nil {
			delete(file.Document, key)
			continue
		}
		if replacement == nil {
			updated := *file.LineOverlay
			updated.Children = make(map[string]*model.LineOverlay, len(file.LineOverlay.Children))
			for name, child := range file.LineOverlay.Children {
				updated.Children[name] = child
			}
			replacement = &updated
		}
		job := *file.LineOverlay.Children[key]
		candidate.Line, _ = candidate.Snapshot.DeclarationSpan(candidate.DocumentIndex, candidate.Line)
		job.Line = candidate.Line
		job.Snapshot = candidate.Snapshot
		job.DocumentIndex = candidate.DocumentIndex
		replacement.Children[key] = &job
	}
	if replacement != nil {
		file.LineOverlay = replacement
	}
}
func earlierSource(position, best model.SourcePosition) bool {
	if best.Snapshot == nil {
		return true
	}
	if position.Snapshot.Path != best.Snapshot.Path {
		return position.Snapshot.Path < best.Snapshot.Path
	}
	if position.DocumentIndex != best.DocumentIndex {
		return position.DocumentIndex < best.DocumentIndex
	}
	return position.Line < best.Line
}

func inScopeJobSource(file *model.FileMetadata, root *model.LineOverlay) model.SourcePosition {
	var best model.SourcePosition
	consider := func(position model.SourcePosition) {
		source := file.SourceFiles[position.Snapshot]
		if source != nil && !source.SourceExcluded && position.Line > 0 && earlierSource(position, best) {
			best = position
		}
	}
	seen := make(map[*model.LineOverlay]bool)
	pending := []*model.LineOverlay{root}
	for len(pending) > 0 {
		node := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if node == nil || node.InheritedDefault || seen[node] {
			continue
		}
		seen[node] = true
		consider(node.Position())
		for _, child := range node.Children {
			pending = append(pending, child)
		}
		for _, span := range node.Ranges {
			consider(span.Position)
		}
	}
	return best
}
