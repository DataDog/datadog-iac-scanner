/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/open-policy-agent/opa/ast"  // nolint:staticcheck
	"github.com/open-policy-agent/opa/rego" // nolint:staticcheck

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/printer"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
)

// RegoValidationError is a single Rego compile-time error with source location.
type RegoValidationError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	StartLine int    `json:"start_line"`
	StartCol  int    `json:"start_col"`
	EndLine   int    `json:"end_line"`
	EndCol    int    `json:"end_col"`
}

// RunCustomRegoQuery writes fileContent to a temp file and runs regoContent against
// it using the same OPA setup as a normal scan. Returns findings, per-query errors,
// and any internal error.
func RunCustomRegoQuery(
	ctx context.Context,
	platform string,
	regoContent string,
	filename string,
	fileContent []byte,
) ([]model.Vulnerability, map[string]error, error) {
	tmpDir, err := os.MkdirTemp("", "iac-custom-scan-*")
	if err != nil {
		return nil, nil, fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	tmpFile := filepath.Join(tmpDir, filename)
	if err := os.WriteFile(tmpFile, fileContent, 0600); err != nil {
		return nil, nil, fmt.Errorf("writing temp file: %w", err)
	}

	params := &Parameters{
		Path:                    []string{tmpFile},
		QueriesPath:             []string{"."},
		LibrariesPath:           source.LibrariesDefaultBasePath,
		PreviewLines:            3,
		CloudProvider:           []string{""},
		Platform:                []string{platform},
		ChangedDefaultQueryPath: true,
		MaxFileSizeFlag:         5,
		QueryExecTimeout:        10,
		ScanID:                  "console",
		MaxResolverDepth:        15,
		FlagEvaluator:           featureflags.NewLocalEvaluator(),
		ExcludeGitIgnore:        true,
	}

	c, err := NewClient(ctx, params, (*printer.Printer)(nil))
	if err != nil {
		return nil, nil, fmt.Errorf("creating scan client: %w", err)
	}

	c.querySourceFactory = func(_ context.Context, _ []string) (source.QueriesSource, error) {
		return &customRegoSource{platform: platform, regoContent: regoContent}, nil
	}

	results, err := c.executeScan(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("executing scan: %w", err)
	}

	if results == nil {
		return nil, nil, nil
	}

	return results.Results, results.FailedQueries, nil
}

// ValidateCustomRegoQuery compiles regoContent against the scanner's OPA setup
// without running a scan. Returns nil on success, or RegoValidationError slice on failure.
func ValidateCustomRegoQuery(
	ctx context.Context,
	platform string,
	regoContent string,
) ([]RegoValidationError, error) {
	fs := source.NewFilesystemSource(ctx, []string{"."}, []string{platform}, []string{""}, source.LibrariesDefaultBasePath, false)

	commonLib, err := fs.GetQueryLibrary(ctx, "common")
	if err != nil {
		return nil, fmt.Errorf("loading common library: %w", err)
	}

	platformLib, err := fs.GetQueryLibrary(ctx, platform)
	if err != nil {
		return nil, fmt.Errorf("loading platform library: %w", err)
	}

	_, compileErr := rego.New( // nolint:staticcheck
		rego.Query(utils.RegoQuery),                     // nolint:staticcheck
		rego.SetRegoVersion(ast.RegoV1),                 // nolint:staticcheck
		rego.Module("Common", commonLib.LibraryCode),    // nolint:staticcheck
		rego.Module("Generic", platformLib.LibraryCode), // nolint:staticcheck
		rego.Module("query.rego", regoContent),          // nolint:staticcheck
		rego.UnsafeBuiltins(map[string]struct{}{ // nolint:staticcheck
			"http.send":   {},
			"opa.runtime": {},
		}),
	).PrepareForEval(ctx)

	if compileErr == nil {
		return nil, nil
	}

	if astErrors, ok := compileErr.(ast.Errors); ok {
		out := make([]RegoValidationError, 0, len(astErrors))
		for _, e := range astErrors {
			ve := RegoValidationError{
				Code:    e.Code,
				Message: e.Message,
			}
			if e.Location != nil {
				ve.StartLine = e.Location.Row
				ve.StartCol = e.Location.Col
				ve.EndLine = e.Location.Row
				ve.EndCol = e.Location.Col + 1
			}
			out = append(out, ve)
		}
		return out, nil
	}

	return []RegoValidationError{{Code: "rego_compile_error", Message: compileErr.Error()}}, nil
}

// customRegoSource is an in-memory QueriesSource that injects a single custom Rego rule.
type customRegoSource struct {
	platform    string
	regoContent string
}

func (s *customRegoSource) GetQueries(_ context.Context, _ *source.QueryInspectorParameters) ([]model.QueryMetadata, error) {
	return []model.QueryMetadata{
		{
			Query:    "custom_rule",
			Content:  s.regoContent,
			Platform: s.platform,
			Metadata: map[string]interface{}{
				"id":            "custom-rule",
				"queryName":     "Custom Rule",
				"severity":      "HIGH",
				"category":      "Custom",
				"platform":      s.platform,
				"cloudProvider": "",
				"aggregation":   1,
			},
			Aggregation: 1,
		},
	}, nil
}

func (s *customRegoSource) GetQueryLibrary(ctx context.Context, libPlatform string) (source.RegoLibraries, error) {
	fs := source.NewFilesystemSource(ctx, []string{"."}, []string{s.platform}, []string{""}, source.LibrariesDefaultBasePath, false)
	return fs.GetQueryLibrary(ctx, libPlatform)
}
