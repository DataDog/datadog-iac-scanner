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
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/provider"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/minified"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	"github.com/DataDog/datadog-iac-scanner/pkg/resolver"

	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/pkg/errors"
)

const (
	mbConst = 1048576
)

// scanReadBufferPool reuses the 1 MiB read buffers handed to getContent so we
// don't allocate (and GC) one per file when scanning large repositories.
var scanReadBufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, mbConst)
		return &b
	},
}

// Storage is the interface that wraps following basic methods: SaveFile, SaveVulnerabilities, and GetVulnerabilities
// SaveFile should append metadata to a file
// SaveVulnerabilities should append vulnerabilities list to current storage
// GetVulnerabilities should returns all vulnerabilities associated to a scan ID
type Storage interface {
	SaveFile(ctx context.Context, metadata *model.FileMetadata) error
	SaveVulnerabilities(ctx context.Context, vulnerabilities []model.Vulnerability) error
	GetVulnerabilities(ctx context.Context, scanID string) ([]model.Vulnerability, error)
}

// Tracker is the interface that wraps the basic methods: TrackFileFound and TrackFileParse
// TrackFileFound should increment the number of files to be scanned
// TrackFileParse should increment the number of files parsed successfully to be scanned
// TrackFileFoundCountResources should increment the number of resources to be scanned
type Tracker interface {
	TrackFileFound(path string)
	TrackFileParse(path string)
	TrackFileFoundCountLines(countLines int)
	TrackFileParseCountLines(countLines int)
	TrackFileIgnoreCountLines(countLines int)
	TrackFileFoundCountResources(countResources int)
}

// Service is a struct that contains a SourceProvider to receive sources, a storage to save and retrieve scanning informations
// a parser to parse and provide files in format the scanner understands, an inspector that runs the scanning and a tracker to
// update scanning numbers
type Service struct {
	SourceProvider provider.SourceProvider
	Storage        Storage
	Parser         *parser.Parser
	Inspector      *engine.Inspector
	Tracker        Tracker
	Resolver       *resolver.Resolver
	files          model.FileMetadatas
	filesMu        sync.Mutex
	MaxFileSize    int
	// Platforms is the scan's effective platform set, used to classify each
	// parsed file's platform consistently with the analyzer so the engine can
	// scope queries to their own platform's documents.
	Platforms []string
	// FilePlatform is the analyzer path → platform map, reused in the sink.
	FilePlatform map[string]string
	// failedHelmChartDirsMu guards failedHelmChartDirs.
	failedHelmChartDirsMu sync.RWMutex
	// failedHelmChartDirs tracks chart directories that could not be rendered,
	// so their raw template files are not mistaken for parse bugs in sink.
	failedHelmChartDirs map[string]struct{}
}

func (s *Service) recordFailedHelmChart(chartDir string) {
	// Absolutize so that relative roots (e.g. ".") match correctly when
	// isUnderFailedHelmChart receives the children reported by filepath.Walk.
	if abs, err := filepath.Abs(chartDir); err == nil {
		chartDir = filepath.ToSlash(abs)
	}
	// Record only the templates/ subtree so that non-template YAML files
	// (values.yaml, crds/, Chart.yaml) still produce Error-level parse
	// failures when they have genuine syntax errors.
	templatesDir := strings.TrimRight(chartDir, "/") + "/templates"
	s.failedHelmChartDirsMu.Lock()
	defer s.failedHelmChartDirsMu.Unlock()
	if s.failedHelmChartDirs == nil {
		s.failedHelmChartDirs = make(map[string]struct{})
	}
	s.failedHelmChartDirs[templatesDir] = struct{}{}
}

func (s *Service) isUnderFailedHelmChart(filePath string) bool {
	s.failedHelmChartDirsMu.RLock()
	defer s.failedHelmChartDirsMu.RUnlock()
	if len(s.failedHelmChartDirs) == 0 {
		return false
	}
	// Normalize to absolute so relative paths (e.g. from a "." root walk)
	// match the absolute dirs stored by recordFailedHelmChart.
	if abs, err := filepath.Abs(filePath); err == nil {
		filePath = filepath.ToSlash(abs)
	}
	for dir := range s.failedHelmChartDirs {
		if strings.HasPrefix(filePath, dir+"/") {
			return true
		}
	}
	return false
}

// PrepareSources will prepare the sources to be scanned
func (s *Service) PrepareSources(ctx context.Context,
	scanID string,
	openAPIResolveReferences bool,
	maxResolverDepth int,
	wg *sync.WaitGroup,
	errCh chan<- error, flagEvaluator featureflags.FlagEvaluator) {
	contextLogger := logger.FromContext(ctx)
	defer wg.Done()
	// CxSAST query under review
	contextLogger.Info().Msgf("Getting sources")
	var err error
	// TODO: Remove this if / else upon finishing dogfooding phase
	if ok := flagEvaluator.EvaluateWithOrgAndEnv(featureflags.IaCEnableKicsParallelFileParsing); ok {
		err = s.SourceProvider.GetParallelSources(
			ctx,
			s.Parser.SupportedExtensions(),
			func(ctx context.Context, filename string, rc io.ReadCloser) error {
				// Buffer is reused across files via a pool; the sink runs
				// concurrently but each call borrows its own buffer.
				buf := scanReadBufferPool.Get().(*[]byte)
				defer scanReadBufferPool.Put(buf)
				return s.sink(ctx, filename, scanID, rc, *buf, openAPIResolveReferences, maxResolverDepth)
			},
			func(ctx context.Context, filename string) ([]string, error) { // Sink used for resolver files and templates
				return s.resolverSink(ctx, filename, scanID, openAPIResolveReferences, maxResolverDepth)
			},
		)
	} else {
		err = s.SourceProvider.GetSources(
			ctx,
			s.Parser.SupportedExtensions(),
			func(ctx context.Context, filename string, rc io.ReadCloser) error {
				buf := scanReadBufferPool.Get().(*[]byte)
				defer scanReadBufferPool.Put(buf)
				return s.sink(ctx, filename, scanID, rc, *buf, openAPIResolveReferences, maxResolverDepth)
			},
			func(ctx context.Context, filename string) ([]string, error) { // Sink used for resolver files and templates
				return s.resolverSink(ctx, filename, scanID, openAPIResolveReferences, maxResolverDepth)
			},
		)
	}
	if err != nil {
		select {
		case errCh <- errors.Wrap(err, "failed to read sources"):
		case <-ctx.Done():
			return
		}
	}
}

// StartScan executes scan over the context, using the scanID as reference
func (s *Service) StartScan(
	ctx context.Context,
	scanID string,
	errCh chan<- error,
	wg *sync.WaitGroup) {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Msg("service.StartScan()")
	defer wg.Done()

	vulnerabilities, err := s.Inspector.Inspect(
		ctx,
		scanID,
		s.files,
		s.Parser.Platform,
	)
	if err != nil {
		select {
		case errCh <- errors.Wrap(err, "failed to inspect files"):
		case <-ctx.Done():
			return
		}
	}

	err = s.Storage.SaveVulnerabilities(ctx, vulnerabilities)
	if err != nil {
		select {
		case errCh <- errors.Wrap(err, "failed to save vulnerabilities"):
		case <-ctx.Done():
			return
		}
	}
}

// Content keeps the content of the file and the number of lines
type Content struct {
	Content        *[]byte
	CountLines     int
	IsMinified     bool
	CountResources int
}

/*
getContent will read the passed file 1MB at a time
to prevent resource exhaustion and return its content
*/
func getContent(rc io.Reader, data []byte, maxSizeMB int, filename string) (*Content, error) {
	var content []byte

	c := &Content{
		Content:    &[]byte{},
		CountLines: 0,
	}

	for {
		if maxSizeMB < 0 {
			return c, errors.New("file size limit exceeded")
		}
		data = data[:cap(data)]
		n, err := rc.Read(data)
		if err != nil {
			if err == io.EOF {
				break
			}
			return c, err
		}
		content = append(content, data[:n]...)
		maxSizeMB--
	}
	c.Content = &content
	// Count lines from the assembled content so chunked reads match a single
	// read (contentFromBytes); the previous per-chunk +1 over-counted.
	c.CountLines = countContentLines(content)
	c.CountResources = GetCountTerraformResources(content)

	c.IsMinified = minified.IsMinified(filename, content)
	return c, nil
}

// countContentLines counts lines the way an editor does: one per newline, plus a
// trailing line when the file does not end in a newline. Shared by getContent
// and contentFromBytes so cached and freshly read files report identical counts.
func countContentLines(content []byte) int {
	count := bytes.Count(content, []byte{'\n'})
	if len(content) > 0 && content[len(content)-1] != '\n' {
		count++
	}
	return count
}

func contentFromBytes(content []byte, maxSizeMB int, filename string) (*Content, error) {
	copied := append([]byte(nil), content...)
	if maxSizeMB >= 0 {
		limit := (maxSizeMB + 1) * mbConst
		if len(copied) > limit {
			return nil, errors.New("file size limit exceeded")
		}
	}
	return &Content{
		Content:        &copied,
		CountLines:     countContentLines(copied),
		IsMinified:     minified.IsMinified(filename, copied),
		CountResources: GetCountTerraformResources(copied),
	}, nil
}

// GetVulnerabilities returns a list of scan detected vulnerabilities
func (s *Service) GetVulnerabilities(ctx context.Context, scanID string) ([]model.Vulnerability, error) {
	return s.Storage.GetVulnerabilities(ctx, scanID)
}

func (s *Service) saveToFile(ctx context.Context, file *model.FileMetadata) {
	err := s.Storage.SaveFile(ctx, file)
	if err == nil {
		s.filesMu.Lock()
		s.files = append(s.files, file)
		s.filesMu.Unlock()
	}
}

// newLineInfoLoader builds a lazy loader that reconstructs a file's line-info
// document by re-parsing OriginalData on demand.
func newLineInfoLoader(
	p *parser.Parser,
	filename string,
	docIdx int,
	openAPIResolveReferences bool,
	isMinified bool,
	maxResolverDepth int,
) func(ctx context.Context, f *model.FileMetadata) (map[string]interface{}, error) {
	return newLineInfoLoaderWithReparser(filename, docIdx,
		func(ctx context.Context, f *model.FileMetadata) (parser.ParsedDocument, error) {
			return p.Parse(
				ctx, filename, []byte(f.OriginalData), openAPIResolveReferences, isMinified, maxResolverDepth)
		})
}

func newLineInfoLoaderWithReparser(
	filename string,
	docIdx int,
	reparse func(context.Context, *model.FileMetadata) (parser.ParsedDocument, error),
) func(ctx context.Context, f *model.FileMetadata) (map[string]interface{}, error) {
	return func(ctx context.Context, f *model.FileMetadata) (map[string]interface{}, error) {
		reparsed, err := reparse(ctx, f)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to reparse %s for line info", filename)
		}
		if docIdx >= len(reparsed.Docs) {
			return nil, errors.Errorf(
				"reparse of %s for line info produced %d documents, expected index %d",
				filename, len(reparsed.Docs), docIdx)
		}
		return reparsed.Docs[docIdx], nil
	}
}

// PrepareScanDocument removes _dd_lines from payload and parses json filters.
// On a marshal failure it logs and returns the original body unchanged.
func PrepareScanDocument(ctx context.Context, body map[string]interface{}, kind model.FileKind) map[string]interface{} {
	bodyMap, err := prepareScanDocument(body, kind)
	if err != nil {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Error().Msgf("failed to remove dd line information: '%s'", err)
		return body
	}
	return bodyMap
}

// prepareScanDocument deep-copies body (via a single JSON round-trip), strips
// _dd_lines and resolves json filters. Returning the error lets callers that
// already gate on marshalability skip the document instead of double-marshaling.
func prepareScanDocument(body map[string]interface{}, kind model.FileKind) (map[string]interface{}, error) {
	j, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	var bodyMap map[string]interface{}
	if err := json.Unmarshal(j, &bodyMap); err != nil {
		return nil, err
	}
	prepareScanDocumentRoot(bodyMap, kind)
	return bodyMap, nil
}

func prepareScanDocumentRoot(body interface{}, kind model.FileKind) {
	prepareScanDocumentNode(body, kind, true, true)
}

// For Terraform-plan documents, pattern rewriting is scoped to the top-level
// "resource" subtree, so resource_changes/configuration stay byte-identical to the raw plan.
func prepareScanDocumentNode(body interface{}, kind model.FileKind, resolveFilters, atDocumentRoot bool) {
	switch bodyType := body.(type) {
	case map[string]interface{}:
		prepareScanDocumentValue(bodyType, kind, resolveFilters, atDocumentRoot)
	case []interface{}:
		for _, indx := range bodyType {
			prepareScanDocumentNode(indx, kind, resolveFilters, false)
		}
	}
}

func prepareScanDocumentValue(bodyType map[string]interface{}, kind model.FileKind, resolveFilters, atDocumentRoot bool) {
	delete(bodyType, "_dd_lines")
	delete(bodyType, "_dd_tf_address")
	for key, v := range bodyType {
		childResolveFilters := resolveFilters
		if kind == model.KindTerraformPlan && atDocumentRoot {
			childResolveFilters = key == "resource"
		}
		switch value := v.(type) {
		case map[string]interface{}:
			prepareScanDocumentNode(value, kind, childResolveFilters, false)
		case []interface{}:
			for _, indx := range value {
				prepareScanDocumentNode(indx, kind, childResolveFilters, false)
			}
		case string:
			if resolveFilters {
				if field, ok := lines[kind]; ok && utils.Contains(key, field) {
					bodyType[key] = resolveJSONFilter(value)
				}
			}
		}
	}
}
