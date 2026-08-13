/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/config"
	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/platforms"
	consolePrinter "github.com/DataDog/datadog-iac-scanner/pkg/printer"
	"github.com/DataDog/datadog-iac-scanner/pkg/scan"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

const (
	// maxRules bounds the number of rules in a single analyze request. The
	// default rule corpus is ~1200 rules; this is generous headroom. The file
	// limit is configurable per-server (Config.MaxFiles), so it is passed in.
	maxRules = defaultMaxRules
	// A library is expected for Common and each supported platform. Keep a
	// generous bound while preventing an accidentally unbounded request array.
	maxLibraries   = 100
	emptyInputData = "{}"
	// commonLibraryID is the id of the shared library every scan requires.
	commonLibraryID = "common"
)

// analyzeFile is a single pushed file: a workspace-relative path and its raw
// (possibly unsaved) content.
type analyzeFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// analyzeRequest is the body of POST /ide/v1/iac/analyze. Ruleset and Libraries
// use the backend data models. Config is the raw YAML of the unified config's
// iac section.
type analyzeRequest struct {
	Files     []analyzeFile     `json:"files"`
	Ruleset   datadog.Ruleset   `json:"ruleset"`
	Libraries []datadog.Library `json:"libraries"`
	Config    string            `json:"config,omitempty"`
	Platform  []string          `json:"platform,omitempty"`
}

// analyzeResponse is the body of a successful analyze. Findings are the engine's
// full vulnerability records (the extension's converter picks the fields it
// needs). MissingFiles drives the hybrid escalation: paths the engine referenced
// but that were not pushed.
type analyzeResponse struct {
	Findings      []model.Vulnerability `json:"findings"`
	MissingFiles  []string              `json:"missing_files"`
	FailedQueries map[string]string     `json:"failed_queries,omitempty"`
}

func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	contextLogger := logger.FromContext(r.Context())

	// Bound concurrent scans before buffering the body or spinning up the
	// engine. Acquire-or-503 so a burst (reachable cross-origin) can't exhaust
	// memory/goroutines; the caller is expected to retry.
	select {
	case s.analyzeSem <- struct{}{}:
		defer func() { <-s.analyzeSem }()
	default:
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusServiceUnavailable, "server busy: too many concurrent analyses")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxRequestBytes)
	var req analyzeRequest
	// Deliberately not DisallowUnknownFields: tolerating unknown fields lets a
	// newer extension talk to an older binary (forward compatibility).
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	if err := validateAnalyzeRequest(&req, s.cfg.MaxFiles); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	out, err := s.analyze(r.Context(), &req)
	if err != nil {
		contextLogger.Err(err).Msg("analyze failed")
		writeError(w, http.StatusInternalServerError, "analysis failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func validateAnalyzeRequest(req *analyzeRequest, maxFiles int) error {
	if len(req.Files) == 0 {
		return errors.New("at least one file is required")
	}
	if len(req.Files) > maxFiles {
		return errors.New("too many files")
	}
	rules := req.Ruleset.Rules
	if len(rules) > maxRules {
		return errors.New("too many rules")
	}
	nonNil := nonNilRules(rules)
	if len(nonNil) == 0 {
		return errors.New("at least one rule is required")
	}
	if err := validateLibraries(req.Libraries, nonNil); err != nil {
		return err
	}
	for _, f := range req.Files {
		if err := validateFilePath(f.Path); err != nil {
			return err
		}
	}
	return nil
}

func nonNilRules(rules []*datadog.Rule) []*datadog.Rule {
	out := make([]*datadog.Rule, 0, len(rules))
	for _, rule := range rules {
		if rule != nil {
			out = append(out, rule)
		}
	}
	return out
}

// publishedRules further narrows nonNilRules to published rules, mirroring
// DatadogSource.filterRules's !rule.IsPublished guard so pushed rulesets
// can't surface findings a normal backend-driven scan would suppress.
func publishedRules(rules []*datadog.Rule) []*datadog.Rule {
	nonNil := nonNilRules(rules)
	out := make([]*datadog.Rule, 0, len(nonNil))
	for _, rule := range nonNil {
		if rule.IsPublished {
			out = append(out, rule)
		}
	}
	return out
}

func validateLibraries(libraries []datadog.Library, rules []*datadog.Rule) error {
	if len(libraries) == 0 {
		return errors.New("at least one library is required")
	}
	if len(libraries) > maxLibraries {
		return errors.New("too many libraries")
	}

	available := make(map[string]struct{}, len(libraries))
	for _, library := range libraries {
		id := normalizePlatform(library.ID)
		if id == "" {
			return errors.New("empty library id")
		}
		if strings.TrimSpace(library.RegoCode) == "" {
			return errors.New("empty library content for " + library.ID)
		}
		if !isOptionalInputDataObject(library.InputData) {
			return errors.New("invalid library input data for " + library.ID)
		}
		available[id] = struct{}{}
	}
	if _, ok := available[commonLibraryID]; !ok {
		return errors.New("common library is required")
	}
	for _, rule := range rules {
		if strings.TrimSpace(rule.Platform) == "" {
			return errors.New("empty platform for rule " + rule.ID)
		}
		key, err := ruleLibraryKey(rule.Platform)
		if err != nil {
			return err
		}
		if _, ok := available[key]; !ok {
			return errors.New("library is required for rule platform: " + rule.Platform)
		}
	}
	return nil
}

func normalizeInputData(inputData string) string {
	if inputData == "" {
		return emptyInputData
	}
	return inputData
}

// isOptionalInputDataObject accepts an omitted input-data value because the
// request conversion normalizes it to {} before passing it to the engine.
func isOptionalInputDataObject(inputData string) bool {
	return inputData == "" || source.IsJSONObject(inputData)
}

// normalizePlatform lowercases and trims a library key for consistent comparison.
func normalizePlatform(platform string) string {
	return strings.ToLower(strings.TrimSpace(platform))
}

// ruleLibraryKey maps a rule's backend platform (e.g. "Kubernetes") to the
// normalized key of the library its queries look up (e.g. "k8s"). It fails
// explicitly when the platform is unrecognized (including casing mismatches
// such as "terraform" vs "Terraform") instead of silently falling through to
// "unknown", which would otherwise surface a misleading "library is required"
// error for the original platform name.
func ruleLibraryKey(platform string) (string, error) {
	mapped := source.GetPlatform(strings.TrimSpace(platform))
	if mapped == source.PlatformUnknown {
		return "", errors.New("unsupported rule platform: " + platform)
	}
	return normalizePlatform(mapped), nil
}

// validateFilePath rejects paths that are empty, absolute, contain a NUL byte,
// or escape the workspace root via "..".
func validateFilePath(p string) error {
	if p == "" {
		return errors.New("empty file path")
	}
	if strings.ContainsRune(p, 0) {
		return errors.New("file path contains NUL byte")
	}
	// filepath.IsAbs is OS-dependent; also reject Unix-style absolute paths on
	// Windows (e.g. "/etc/passwd" is not absolute per Windows rules).
	if filepath.IsAbs(p) || strings.HasPrefix(p, "/") {
		return errors.New("file path must be workspace-relative, got absolute: " + p)
	}
	clean := filepath.ToSlash(filepath.Clean(p))
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return errors.New("file path escapes the workspace: " + p)
	}
	return nil
}

// analyze runs the content-push scan: build an in-memory FS from the pushed
// files, serve the request's rules, and run the engine with no disk, git, or
// network access. It returns the findings plus the list of files the engine
// referenced but did not receive.
func (s *Server) analyze(ctx context.Context, req *analyzeRequest) (*analyzeResponse, error) {
	contextLogger := logger.FromContext(ctx)
	files := make(map[string][]byte, len(req.Files))
	for _, f := range req.Files {
		files[f.Path] = []byte(f.Content)
	}
	memfs := vfs.NewMemFS(files)

	cfg := config.IacConfig{}
	if strings.TrimSpace(req.Config) != "" {
		parsed, err := config.ParseConfig([]byte(req.Config))
		if err != nil {
			return nil, err
		}
		// ParseConfig returns (nil, nil) for a valid config that has no `iac`
		// section. Keep the empty IaC config in that case.
		if parsed != nil {
			cfg = *parsed
		}
	}

	plats := make([]string, len(req.Platform))
	for i, platform := range req.Platform {
		plats[i] = normalizePlatform(platform)
	}
	if len(plats) == 0 {
		plats = platforms.Supported
	}

	params := &scan.Parameters{
		CloudProvider:    []string{""},
		Path:             memfs.Paths(),
		RepoPath:         "", // no git in server mode
		PreviewLines:     3,
		Platform:         plats,
		DisableSecrets:   true,
		ScanID:           "serve",
		MaxFileSizeFlag:  100,
		MaxResolverDepth: 15,
		// Helm rendering shells out to a chart on disk, which content-push mode
		// has no way to materialize, so disable the resolver. Parallel file
		// parsing fans the per-file parse across CPUs; enabled by default and
		// can be disabled with --x-parallelparsing=false.
		FlagEvaluator: featureflags.NewLocalEvaluatorWithOverrides(map[string]bool{
			featureflags.IacEnableKicsHelmResolver:        false,
			featureflags.IaCEnableKicsParallelFileParsing: s.cfg.ParallelParsing,
		}),
		Config:               cfg,
		DisableRuleIsolation: s.cfg.DisableRuleIsolation,
		UseRulesCache:        s.cfg.UseRulesCache,
	}

	client, err := scan.NewClient(ctx, params, &consolePrinter.Printer{},
		scan.WithFS(memfs),
		scan.WithInMemoryScan(memfs.Paths()),
		scan.WithQuerySourceFactory(querySourceFactory(req.Ruleset.Rules, req.Libraries)),
	)
	if err != nil {
		return nil, err
	}

	res, err := client.Scan(ctx)
	if err != nil {
		return nil, err
	}

	resp := &analyzeResponse{
		Findings:     []model.Vulnerability{},
		MissingFiles: memfs.MissingFiles(),
	}
	if res == nil {
		// No analyzable content for the requested platforms.
		return resp, nil
	}
	if len(res.Results) > 0 {
		resp.Findings = res.Results
	}
	if len(res.FailedQueries) > 0 {
		contextLogger.Warn().
			Int("failed_query_count", len(res.FailedQueries)).
			Msg("IaC analysis completed with failed queries")
		resp.FailedQueries = make(map[string]string, len(res.FailedQueries))
		for q, e := range res.FailedQueries {
			resp.FailedQueries[q] = e.Error()
		}
	}
	return resp, nil
}

// querySourceFactory returns a factory that serves rules and libraries only
// from the analyze request.
func querySourceFactory(rules []*datadog.Rule, libraries []datadog.Library) func(
	context.Context, []string,
) (source.QueriesSource, error) {
	return func(context.Context, []string) (source.QueriesSource, error) {
		return &requestQuerySource{
			queries:   toQueryMetadata(rules),
			libraries: toRegoLibraries(libraries),
		}, nil
	}
}

// requestQuerySource serves the request's rules and libraries without disk or
// network access.
type requestQuerySource struct {
	queries   []model.QueryMetadata
	libraries map[string]source.RegoLibraries
}

func (r *requestQuerySource) GetQueries(ctx context.Context, params *source.QueryInspectorParameters) ([]model.QueryMetadata, error) {
	// Apply the same use-rules/ignore-rules, severity/category, and feature-flag
	// filters the filesystem source applies, so config-disabled rules stay
	// suppressed even when the caller pushes them in the request.
	return source.FilterQueries(ctx, r.queries, params), nil
}

func (r *requestQuerySource) GetQueryLibrary(ctx context.Context, platform string) (source.RegoLibraries, error) {
	library, ok := r.libraries[normalizePlatform(platform)]
	if !ok {
		return source.RegoLibraries{}, errors.New("library not found in request: " + platform)
	}
	return library, nil
}

func toRegoLibraries(libraries []datadog.Library) map[string]source.RegoLibraries {
	out := make(map[string]source.RegoLibraries, len(libraries))
	for _, library := range libraries {
		out[normalizePlatform(library.ID)] = source.RegoLibraries{
			LibraryCode:      library.RegoCode,
			LibraryInputData: normalizeInputData(library.InputData),
		}
	}
	return out
}

// toQueryMetadata converts request rules into engine query metadata via the
// shared Datadog API conversion.
func toQueryMetadata(rules []*datadog.Rule) []model.QueryMetadata {
	usable := publishedRules(rules)
	out := make([]model.QueryMetadata, 0, len(usable))
	for _, rule := range usable {
		// Copy so trimming the platform does not mutate the shared request value.
		r := *rule
		r.Platform = strings.TrimSpace(r.Platform)
		out = append(out, source.ConvertRule(&r))
	}
	return out
}

// compile-time assertion that requestQuerySource satisfies the engine interface.
var _ source.QueriesSource = (*requestQuerySource)(nil)
