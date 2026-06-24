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
	"maps"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/config"
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
	// maxFiles / maxRules bound a single analyze request. The default rule corpus
	// is ~1200 rules; the limits are generous headroom, not a tuning knob.
	maxFiles = 5000
	maxRules = 10000
	// metadataDefaultKeys is the number of fixed keys setDefault injects in
	// toQueryMetadata (id, legacyId, queryName, severity, platform, category).
	metadataDefaultKeys = 6
)

// analyzeFile is a single pushed file: a workspace-relative path and its raw
// (possibly unsaved) content.
type analyzeFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// analyzeRule is a single Rego rule supplied by the caller. Mirrors the shape
// the extension already builds for the engine.
type analyzeRule struct {
	ID        string         `json:"id"`
	Platform  string         `json:"platform"`
	Content   string         `json:"content"`
	InputData string         `json:"inputData,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// analyzeRequest is the body of POST /ide/v1/iac/analyze. Content is raw (not
// base64). Rules are pushed by the extension; an empty list falls back to the
// embedded corpus. Config is the raw YAML of the unified config's iac section.
type analyzeRequest struct {
	Files    []analyzeFile `json:"files"`
	Rules    []analyzeRule `json:"rules"`
	Config   string        `json:"config,omitempty"`
	Platform []string      `json:"platform,omitempty"`
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

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
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

	if err := validateAnalyzeRequest(&req); err != nil {
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

func validateAnalyzeRequest(req *analyzeRequest) error {
	if len(req.Files) == 0 {
		return errors.New("at least one file is required")
	}
	if len(req.Files) > maxFiles {
		return errors.New("too many files")
	}
	if len(req.Rules) > maxRules {
		return errors.New("too many rules")
	}
	for _, f := range req.Files {
		if err := validateFilePath(f.Path); err != nil {
			return err
		}
	}
	return nil
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
		cfg = *parsed
	}

	plats := req.Platform
	if len(plats) == 0 {
		plats = platforms.Supported
	}

	params := &scan.Parameters{
		CloudProvider:    []string{""},
		Path:             memfs.Paths(),
		RepoPath:         "", // no git in server mode
		QueriesPath:      []string{s.cfg.QueriesPath},
		LibrariesPath:    s.cfg.LibrariesPath,
		PreviewLines:     3,
		Platform:         plats,
		DisableSecrets:   true,
		ScanID:           "serve",
		MaxFileSizeFlag:  100,
		MaxResolverDepth: 15,
		// Helm rendering shells out to a chart on disk, which content-push mode
		// has no way to materialize, so disable the resolver. Parallel file
		// parsing is pointless for in-memory content.
		FlagEvaluator: featureflags.NewLocalEvaluatorWithOverrides(map[string]bool{
			featureflags.IacEnableKicsHelmResolver:        false,
			featureflags.IaCEnableKicsParallelFileParsing: false,
		}),
		Config: cfg,
	}

	client, err := scan.NewClient(ctx, params, &consolePrinter.Printer{},
		scan.WithFS(memfs),
		scan.WithInMemoryScan(memfs.Paths()),
		scan.WithQuerySourceFactory(s.querySourceFactory(params, req.Rules)),
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
		resp.FailedQueries = make(map[string]string, len(res.FailedQueries))
		for q, e := range res.FailedQueries {
			resp.FailedQueries[q] = e.Error()
		}
	}
	return resp, nil
}

// querySourceFactory returns a factory that serves the request's rules (with
// libraries loaded from the embedded corpus). When no rules are pushed it falls
// back to the filesystem corpus directly — never the network-backed Datadog
// source, keeping the request path pure.
func (s *Server) querySourceFactory(
	params *scan.Parameters, rules []analyzeRule,
) func(context.Context, []string) (source.QueriesSource, error) {
	return func(ctx context.Context, plats []string) (source.QueriesSource, error) {
		fsSource := source.NewFilesystemSource(ctx, params.QueriesPath, plats,
			params.CloudProvider, params.LibrariesPath, params.ExperimentalQueries)
		if len(rules) == 0 {
			return fsSource, nil
		}
		return &requestQuerySource{queries: toQueryMetadata(rules), libraries: fsSource}, nil
	}
}

// requestQuerySource serves the request's rules as queries while delegating
// library loading to the embedded filesystem source.
type requestQuerySource struct {
	queries   []model.QueryMetadata
	libraries source.QueriesSource
}

func (r *requestQuerySource) GetQueries(_ context.Context, _ *source.QueryInspectorParameters) ([]model.QueryMetadata, error) {
	return r.queries, nil
}

func (r *requestQuerySource) GetQueryLibrary(ctx context.Context, platform string) (source.RegoLibraries, error) {
	return r.libraries.GetQueryLibrary(ctx, platform)
}

// toQueryMetadata converts request rules into engine query metadata, filling the
// metadata fields the vulnerability builder expects when the caller omits them.
func toQueryMetadata(rules []analyzeRule) []model.QueryMetadata {
	out := make([]model.QueryMetadata, 0, len(rules))
	for _, rule := range rules {
		inputData := rule.InputData
		if inputData == "" {
			inputData = "{}"
		}
		// Copy the caller's metadata into a fresh map so this function never
		// mutates the request value (which may be shared/read concurrently).
		metadata := make(map[string]any, len(rule.Metadata)+metadataDefaultKeys)
		maps.Copy(metadata, rule.Metadata)
		setDefault(metadata, "id", rule.ID)
		setDefault(metadata, "legacyId", rule.ID)
		setDefault(metadata, "queryName", rule.ID)
		setDefault(metadata, "severity", "INFO")
		setDefault(metadata, "platform", rule.Platform)
		setDefault(metadata, "category", "Best Practices")

		out = append(out, model.QueryMetadata{
			Query:     rule.ID,
			Content:   rule.Content,
			InputData: inputData,
			Platform:  rule.Platform,
			Metadata:  metadata,
		})
	}
	return out
}

func setDefault(m map[string]any, key string, value any) {
	if _, ok := m[key]; !ok {
		m[key] = value
	}
}

// compile-time assertion that requestQuerySource satisfies the engine interface.
var _ source.QueriesSource = (*requestQuerySource)(nil)
