/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package runner

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

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
	// terraformPlanResourceKey is the top-level subtree whose pattern
	// rewriting is preserved verbatim in Terraform-plan documents.
	terraformPlanResourceKey = "resource"
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
	// contentInterner dedups OriginalData strings across files with identical
	// content. Large repositories (e.g. community-operators) ship the same
	// CRD/manifest across many operator versions, so 47%+ of files can be exact
	// duplicates; sharing one string backing array cuts the retained content
	// roughly in half. Guarded by contentInternerMu.
	contentInternerMu sync.Mutex
	contentInterner   map[string]string
	// parsedShareMu guards parsedShares, the content-keyed cache of parse results
	// shared between files with identical content (see sharedParse).
	parsedShareMu sync.Mutex
	parsedShares  map[string]*sharedParse
	// treeCons canonicalizes structurally identical subtrees of sanitized
	// shareable documents (see treeHashCons); guarded by treeConsMu.
	treeConsMu sync.Mutex
	treeCons   *treeHashCons
}

// consTreeChildren canonicalizes a sanitized shareable document's subtrees
// through the service-wide tree interner.
func (s *Service) consTreeChildren(doc map[string]interface{}) map[string]interface{} {
	s.treeConsMu.Lock()
	defer s.treeConsMu.Unlock()
	if s.treeCons == nil {
		s.treeCons = newTreeHashCons()
	}
	return s.treeCons.consChildren(doc)
}

// sharedParse holds everything about parsing one file content that is a pure
// function of that content: the sanitized document trees (with all children
// shared), kind, ignore lines and line counts. community-operators-class
// repositories ship the same manifest for many operator versions, so a large
// fraction of files are exact duplicates; sharing one parse per unique content
// cuts both the parsed-tree heap and (through the payload build's pointer
// memo) the OPA payload proportionally.
//
// The cached top-level document maps are never handed out directly: callers
// take a shallow per-file copy (same children, fresh top-level map) because
// Combine inserts each file's id/file into its Document top level.
type sharedParse struct {
	docs        []model.Document
	kind        model.FileKind
	ignoreLines []int
	countLines  int
	isMinified  bool
}

// contentInternerMaxBytes caps the size of content eligible for interning.
// Above this, a single map key's string copy costs more than the duplication
// it would save, and huge files are rarely duplicated.
const contentInternerMaxBytes = 1 << 20 // 1 MiB

// internContent returns a shared copy of content. Identical content strings
// map to the same backing array, so duplicate files retain a single copy of
// OriginalData instead of one per file. The map key is the content itself; for
// interned entries the key string shares storage with the value, so the
// overhead is one map slot per unique file.
//
// ClearContentInterner drops the interner map after the prepare phase so its
// map entries (which pin the shared strings) don't defeat the post-eval
// OriginalData release. The shared strings stay alive via FileMetadata until
// those are released.
func (s *Service) internContent(content string) string {
	if content == "" || len(content) > contentInternerMaxBytes {
		return content
	}
	s.contentInternerMu.Lock()
	defer s.contentInternerMu.Unlock()
	if s.contentInterner == nil {
		s.contentInterner = make(map[string]string)
	}
	if existing, ok := s.contentInterner[content]; ok {
		return existing
	}
	s.contentInterner[content] = content
	return content
}

// ClearContentInterner drops the content interner map. Call after the prepare
// phase: the map's keys pin the shared content strings, which would otherwise
// defeat the post-eval OriginalData release. The strings remain alive via
// FileMetadata.OriginalData until those are released.
func (s *Service) ClearContentInterner() {
	s.contentInternerMu.Lock()
	s.contentInterner = nil
	s.contentInternerMu.Unlock()
}

// lookupSharedParse interns the raw (CRLF-normalized) file content and returns
// the interned key plus the cached shared parse for it, or a nil sharedParse
// when this content has not been cached yet (or is not cacheable by size).
// The key/content match is exact: every parse is a pure function of its
// content, so a hit is a faithful shortcut for files with identical bytes.
// The returned sharedParse is read-only; callers must copy the top-level
// document maps before attaching per-file entries (see Combine).
func (s *Service) lookupSharedParse(content []byte) (string, *sharedParse) {
	if len(content) == 0 || len(content) > contentInternerMaxBytes {
		return "", nil
	}
	key := s.internContent(string(content))
	s.parsedShareMu.Lock()
	shared := s.parsedShares[key]
	s.parsedShareMu.Unlock()
	return key, shared
}

// storeSharedParse caches a sanitized parse result for later files with the
// same content. docs are the sanitized top-level maps; each is shallow-copied
// so Combine's per-file id/file insertion cannot touch the cached entries.
func (s *Service) storeSharedParse(key string, documents *parser.ParsedDocument, docs []model.Document) {
	cached := make([]model.Document, len(docs))
	for i, d := range docs {
		cached[i] = cloneDocumentTopLevel(d)
	}
	s.parsedShareMu.Lock()
	if s.parsedShares == nil {
		s.parsedShares = make(map[string]*sharedParse)
	}
	s.parsedShares[key] = &sharedParse{
		docs:        cached,
		kind:        documents.Kind,
		ignoreLines: documents.IgnoreLines,
		countLines:  documents.CountLines,
		isMinified:  documents.IsMinified,
	}
	s.parsedShareMu.Unlock()
}

// ClearParsedShares drops the shared parse cache. Call after the prepare
// phase: the map pins both the content keys and the shared trees; the trees
// stay alive via each FileMetadata's document copy.
func (s *Service) ClearParsedShares() {
	s.parsedShareMu.Lock()
	s.parsedShares = nil
	s.parsedShareMu.Unlock()
}

// ClearTreeCons drops the tree hash-cons interner's bookkeeping. Call after
// the prepare phase alongside the other interning caches: the interner maps
// can hold tens of MB of pure map overhead on corpora with hundreds of
// thousands of distinct subtrees, and nothing is consed after prepare. The
// shared trees themselves stay alive via each FileMetadata's document copy,
// so only the interner maps are dropped.
func (s *Service) ClearTreeCons() {
	s.treeConsMu.Lock()
	s.treeCons = nil
	s.treeConsMu.Unlock()
}

// shareableParse reports whether a parse result is a pure function of its
// content and safe to share between files. Excluded are:
//   - Terraform and Terraform-plan documents (local-module instantiation later
//     mutates module bodies in place per caller)
//   - parses that resolved external references (their ResolvedFiles and
//     ignore lines are filename-relative)
//   - Ansible playbooks (AddExtraInfo rewrites them per file path)
//   - empty or oversized content (the dedup win never pays for the key)
func shareableParse(documents *parser.ParsedDocument) bool {
	if documents.Content == "" || len(documents.Content) > contentInternerMaxBytes {
		return false
	}
	switch documents.Kind {
	case model.KindTerraform, model.KindTerraformPlan:
		return false
	}
	if len(documents.ResolvedFiles) > 0 || len(documents.Docs) == 0 {
		return false
	}
	for _, doc := range documents.Docs {
		if _, ok := doc["playbooks"]; ok {
			return false
		}
	}
	return true
}

// cloneDocumentTopLevel returns a shallow copy of a document's top-level map:
// a fresh map with the same key/value pairs, so children (the bulk of the
// tree) remain shared while the copy can carry per-file entries such as the
// id/file keys Combine inserts.
func cloneDocumentTopLevel(d model.Document) model.Document {
	clone := make(model.Document, len(d)+2)
	for k, v := range d {
		clone[k] = v
	}
	return clone
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

// FileCount returns the number of files this service has collected so far.
// Used to size scan-phase GC tuning; the mutex makes it safe to call while
// prepare is still running.
func (s *Service) FileCount() int {
	s.filesMu.Lock()
	defer s.filesMu.Unlock()
	return len(s.files)
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

// errCyclicDocument is returned by sanitizeScanDocumentInPlace when a YAML
// anchor/alias cycle is detected. The JSON round-trip path rejects such
// documents via json.Marshal and skips them; this sentinel preserves that
// behavior for the in-place path.
var errCyclicDocument = errors.New("cyclic document tree")

// sanitizeScanDocumentInPlace strips _dd_lines and resolves JSON filters
// directly on body, avoiding the JSON round-trip deep copy that
// prepareScanDocument performs. The deep copy duplicates the entire document
// tree in memory for every file and is the dominant heap/CPU cost on large
// repositories; it is only needed when body is shared with the line-info
// document (so it must not be mutated). After the lazy line-info refactor the
// main file sink reconstructs LineInfoDocument by reparsing OriginalData, so
// body is exclusively owned and can be sanitized in place — exactly as the
// Helm resolved path already does.
//
// YAML anchors/aliases can form cycles, which json.Marshal rejects; we detect
// cycles with a pointer-identity recursion stack and return errCyclicDocument
// so the caller skips the document, preserving the round-trip path's behavior.
func sanitizeScanDocumentInPlace(body map[string]interface{}, kind model.FileKind) (map[string]interface{}, error) {
	stack := make(map[uintptr]bool)
	if err := sanitizeScanDocumentNodeInPlace(body, kind, true, true, stack); err != nil {
		return nil, err
	}
	return body, nil
}

func sanitizeScanDocumentNodeInPlace(
	body interface{},
	kind model.FileKind,
	resolveFilters, atDocumentRoot bool,
	stack map[uintptr]bool,
) error {
	switch bodyType := body.(type) {
	case map[string]interface{}:
		return sanitizeScanDocumentValueInPlace(bodyType, kind, resolveFilters, atDocumentRoot, stack)
	case []interface{}:
		for i, indx := range bodyType {
			if !isCanonicalDocumentValue(indx) {
				if normalized, changed := normalizeDocumentValue(indx); changed {
					bodyType[i] = normalized
				}
			}
			if err := sanitizeScanDocumentNodeInPlace(bodyType[i], kind, resolveFilters, false, stack); err != nil {
				return err
			}
		}
	}
	return nil
}

func sanitizeScanDocumentValueInPlace(
	bodyType map[string]interface{},
	kind model.FileKind,
	resolveFilters, atDocumentRoot bool,
	stack map[uintptr]bool,
) error {
	ptr := reflect.ValueOf(bodyType).Pointer()
	if stack[ptr] {
		return errCyclicDocument
	}
	stack[ptr] = true
	defer delete(stack, ptr)

	delete(bodyType, "_dd_lines")
	for key, v := range bodyType {
		childResolveFilters := resolveFilters
		if kind == model.KindTerraformPlan && atDocumentRoot {
			childResolveFilters = key == terraformPlanResourceKey
		}
		switch value := v.(type) {
		case map[string]interface{}:
			if err := sanitizeScanDocumentNodeInPlace(value, kind, childResolveFilters, false, stack); err != nil {
				return err
			}
		case []interface{}:
			for _, indx := range value {
				if err := sanitizeScanDocumentNodeInPlace(indx, kind, childResolveFilters, false, stack); err != nil {
					return err
				}
			}
		case string:
			if resolveFilters {
				if field, ok := lines[kind]; ok && utils.Contains(key, field) {
					bodyType[key] = resolveJSONFilter(value)
				}
			}
		default:
			if err := sanitizeNormalizedValueInPlace(bodyType, key, kind, childResolveFilters, stack); err != nil {
				return err
			}
		}
	}
	return nil
}

// sanitizeNormalizedValueInPlace handles a map entry whose value is of a
// non-canonical Go type (e.g. map[string]string produced by the Terraform
// aws_iam_policy_document data-source path, []string, int, json.Number).
// prepareScanDocument's JSON round-trip used to canonicalize these; without
// it they reach interfaceToPayloadValue's default branch, which bypasses the
// shared pointer memo and re-builds every converted object through
// TransformJsonencodeInPayload — inflating the OPA payload several-fold on
// Terraform-heavy repositories. The value is normalized in place and the
// walk continues into the normalized container so nested exotics are covered.
func sanitizeNormalizedValueInPlace(
	bodyType map[string]interface{},
	key string,
	kind model.FileKind,
	resolveFilters bool,
	stack map[uintptr]bool,
) error {
	if normalized, changed := normalizeDocumentValue(bodyType[key]); changed {
		bodyType[key] = normalized
	}
	switch value := bodyType[key].(type) {
	case map[string]interface{}:
		return sanitizeScanDocumentNodeInPlace(value, kind, resolveFilters, false, stack)
	case []interface{}:
		for _, indx := range value {
			if err := sanitizeScanDocumentNodeInPlace(indx, kind, resolveFilters, false, stack); err != nil {
				return err
			}
		}
	}
	return nil
}

// isCanonicalDocumentValue reports whether v is one of the value types the
// removed JSON round-trip produced and every consumer downstream of the sink
// (OPA payload conversion, detectors, JSON payload export) expects.
func isCanonicalDocumentValue(v interface{}) bool {
	switch v.(type) {
	case nil, bool, string, float64, map[string]interface{}, []interface{}:
		return true
	}
	return false
}

// normalizeDocumentValue converts a non-canonical document value to the
// representation the old prepareScanDocument JSON round-trip produced, in
// place of that round-trip: nested maps become map[string]interface{},
// slices become []interface{}, numbers become float64, []byte becomes a
// base64 string, and json.Number becomes the float64 json.Unmarshal yields.
// It returns the replacement value and whether anything changed. Canonical
// values (including whole canonical subtrees) are returned unchanged at zero
// cost, so YAML repositories with already-canonical trees pay nothing.
func normalizeDocumentValue(v interface{}) (interface{}, bool) {
	if isCanonicalDocumentValue(v) {
		return v, false
	}
	if normalized, handled := normalizeScalarDocumentValue(v); handled {
		return normalized, true
	}
	switch t := v.(type) {
	case []string:
		out := make([]interface{}, len(t))
		for i, e := range t {
			out[i] = e
		}
		return out, true
	case map[string]string:
		out := make(map[string]interface{}, len(t))
		for k, e := range t {
			out[k] = e
		}
		return out, true
	case map[interface{}]interface{}:
		// yaml.v3 produces these only for non-string keys; string keys convert
		// exactly as the JSON round-trip did (values included).
		return normalizeInterfaceKeyedMap(t), true
	}

	// Reflect fallback for the remaining container shapes seen in parsed
	// documents (map[string]T with non-scalar T, []map[string]string, ...).
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map:
		if rv.Type().Key().Kind() == reflect.String {
			return normalizeReflectedStringMap(rv), true
		}
	case reflect.Slice, reflect.Array:
		return normalizeSliceDocumentValue(rv), true
	}
	return v, false
}

// normalizeInterfaceKeyedMap converts a map[interface{}]interface{} (yaml.v3
// produces these only for non-string keys) to a map[string]interface{},
// normalizing each value exactly as the JSON round-trip did.
func normalizeInterfaceKeyedMap(t map[interface{}]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(t))
	for k, e := range t {
		if ks, ok := k.(string); ok {
			if normalized, changed := normalizeDocumentValue(e); changed {
				out[ks] = normalized
			} else {
				out[ks] = e
			}
		}
	}
	return out
}

// normalizeReflectedStringMap converts any reflect-visible map with string
// keys to map[string]interface{}, normalizing each value.
func normalizeReflectedStringMap(rv reflect.Value) map[string]interface{} {
	out := make(map[string]interface{}, rv.Len())
	iter := rv.MapRange()
	for iter.Next() {
		mk := iter.Key().String()
		mv := iter.Value().Interface()
		if normalized, changed := normalizeDocumentValue(mv); changed {
			out[mk] = normalized
		} else {
			out[mk] = mv
		}
	}
	return out
}

// normalizeIntegerDocumentValue widens every integer width to the float64
// that json.Unmarshal produced for any JSON number.
func normalizeIntegerDocumentValue(v interface{}) (float64, bool) {
	switch t := v.(type) {
	case int:
		return float64(t), true
	case int8:
		return float64(t), true
	case int16:
		return float64(t), true
	case int32:
		return float64(t), true
	case int64:
		return float64(t), true
	case uint:
		return float64(t), true
	case uint8:
		return float64(t), true
	case uint16:
		return float64(t), true
	case uint32:
		return float64(t), true
	case uint64:
		return float64(t), true
	}
	return 0, false
}

// normalizeScalarDocumentValue converts the scalar types the removed JSON
// round-trip re-emitted as float64 / string. It reports whether v was one of
// them (the second return is the replacement, valid only when handled).
func normalizeScalarDocumentValue(v interface{}) (interface{}, bool) {
	if normalized, handled := normalizeIntegerDocumentValue(v); handled {
		return normalized, true
	}
	switch t := v.(type) {
	case float32:
		// Match json.Marshal's shortest float32 representation, which the old
		// round-trip then re-read as float64 (a direct float64(t) conversion
		// would widen 0.1 to 0.10000000149011612 and change rule-visible values).
		s := strconv.FormatFloat(float64(t), 'g', -1, 32)
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return float64(t), true
		}
		return f, true
	case json.Number:
		f, err := t.Float64()
		if err != nil {
			return nil, false
		}
		return f, true
	case []byte:
		// json.Marshal encodes []byte as a base64 string.
		return base64.StdEncoding.EncodeToString(t), true
	case time.Time:
		return t.Format(time.RFC3339Nano), true
	}
	return nil, false
}

// normalizeSliceDocumentValue converts an arbitrary-typed slice or array to
// []interface{}, normalizing each element.
func normalizeSliceDocumentValue(rv reflect.Value) []interface{} {
	out := make([]interface{}, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		ev := rv.Index(i).Interface()
		if normalized, changed := normalizeDocumentValue(ev); changed {
			out[i] = normalized
		} else {
			out[i] = ev
		}
	}
	return out
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
	for key, v := range bodyType {
		childResolveFilters := resolveFilters
		if kind == model.KindTerraformPlan && atDocumentRoot {
			childResolveFilters = key == terraformPlanResourceKey
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
