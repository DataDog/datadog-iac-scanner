/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"

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
	fileContent []byte,
) ([]model.Vulnerability, map[string]error, error) {
	tmpDir, err := os.MkdirTemp("", "iac-custom-scan-*")
	if err != nil {
		return nil, nil, fmt.Errorf("creating temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	const ownerReadWritePerm = 0o600
	tmpFile := filepath.Join(tmpDir, "scan-target")
	if err := os.WriteFile(tmpFile, fileContent, ownerReadWritePerm); err != nil {
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
		QueryExecTimeout:        10, // shorter than the CLI default; custom rules should be fast
		ScanID:                  "console",
		MaxResolverDepth:        15,
		FlagEvaluator:           featureflags.NewLocalEvaluator(),
		ExcludeGitIgnore:        true,
	}

	c, err := NewClient(ctx, params, (*printer.Printer)(nil))
	if err != nil {
		return nil, nil, fmt.Errorf("creating scan client: %w", err)
	}

	c.analyzerOverride = func(_ context.Context) (model.AnalyzedPaths, error) {
		return model.AnalyzedPaths{Types: []string{platform}}, nil
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

	narrowToAttributeLocation(results.Results)
	return results.Results, results.FailedQueries, nil
}

// ValidateCustomRegoQuery compiles regoContent against the scanner's OPA setup
// without running a scan. On success it returns (nil, nil). On validation failure it
// returns a non-empty []RegoValidationError and a nil error.
func ValidateCustomRegoQuery(
	ctx context.Context,
	platform string,
	regoContent string,
) ([]RegoValidationError, error) {
	// Check structural constraints that OPA won't catch at compile time: the scanner
	// evaluates `result = data.datadog.DatadogPolicy`, so the module must declare
	// `package datadog` and at least one `DatadogPolicy` rule.
	if errs := validateRegoStructure(regoContent); len(errs) > 0 {
		return errs, nil
	}

	fs := libraryFilesystemSource(ctx, platform)

	commonLib, err := fs.GetQueryLibrary(ctx, "common")
	if err != nil {
		return nil, fmt.Errorf("loading common library: %w", err)
	}

	platformLib, err := fs.GetQueryLibrary(ctx, platform)
	if err != nil {
		return nil, fmt.Errorf("loading platform library: %w", err)
	}

	_, compileErr := rego.New(
		rego.Query(utils.RegoQuery),
		rego.SetRegoVersion(ast.RegoV1),
		rego.Module("Common", commonLib.LibraryCode),
		rego.Module("Generic", platformLib.LibraryCode),
		rego.Module("query.rego", regoContent),
		rego.UnsafeBuiltins(map[string]struct{}{
			"http.send":   {},
			"opa.runtime": {},
		}),
	).PrepareForEval(ctx)

	if compileErr == nil {
		return nil, nil
	}

	return regoValidationErrorsFrom(compileErr), nil
}

// validateRegoStructure parses regoContent and checks constraints that OPA's compiler
// will not report as errors but that will silently produce zero findings:
//   - the module must declare `package datadog`
//   - at least one rule named `DatadogPolicy` must exist
//
// Parse errors from ast.ParseModule are returned directly as validation errors so the
// caller gets line-accurate markers without going through the full compile pipeline.
func validateRegoStructure(regoContent string) []RegoValidationError {
	module, err := ast.ParseModuleWithOpts("query.rego", regoContent, ast.ParserOptions{
		ProcessAnnotation: false,
		RegoVersion:       ast.RegoV1,
	})
	if err != nil {
		return regoValidationErrorsFrom(err)
	}

	var errs []RegoValidationError

	if module.Package.Path.String() != "data.datadog" {
		errs = append(errs, RegoValidationError{
			Code:    "invalid_package",
			Message: fmt.Sprintf("package must be 'datadog', got %q — the scanner evaluates data.datadog.DatadogPolicy", module.Package.Path.String()),
		})
	}

	hasPolicy := false
	for _, rule := range module.Rules {
		if rule.Head.Name == "DatadogPolicy" {
			hasPolicy = true
			break
		}
	}
	if !hasPolicy {
		errs = append(errs, RegoValidationError{
			Code:    "missing_rule",
			Message: "no 'DatadogPolicy' rule found — the scanner evaluates data.datadog.DatadogPolicy so the rule must use that exact name",
		})
	}

	return errs
}

// regoValidationErrorsFrom converts an error returned by OPA (ast.Errors, or anything
// wrapping it) into a []RegoValidationError with accurate line/column information.
// It tries a direct type assertion first (most reliable for ast.Errors, a slice type),
// then errors.As for wrapped errors, and finally falls back to a single message-only
// error so callers always get something actionable.
func regoValidationErrorsFrom(err error) []RegoValidationError {
	// Direct type assertion: OPA commonly returns ast.Errors as a concrete value.
	// errors.As struggles with non-pointer slice types so we prefer this path.
	if astErrs, ok := err.(ast.Errors); ok {
		out := make([]RegoValidationError, 0, len(astErrs))
		for _, e := range astErrs {
			out = append(out, regoValidationErrorFromAST(e))
		}
		return out
	}

	// Fallback: try errors.As in case the error is wrapped.
	var wrapped ast.Errors
	if errors.As(err, &wrapped) {
		out := make([]RegoValidationError, 0, len(wrapped))
		for _, e := range wrapped {
			out = append(out, regoValidationErrorFromAST(e))
		}
		return out
	}

	return []RegoValidationError{{Code: ast.CompileErr, Message: err.Error()}}
}

// narrowToAttributeLocation narrows VulnerabilityLocation to the precise attribute-level
// location when it falls within the resource block, giving callers single-line highlight
// precision. Mirrors the equivalent logic in pkg/report/model/sarif.go.
func narrowToAttributeLocation(vulns []model.Vulnerability) {
	for i := range vulns {
		v := &vulns[i]

		res := &v.VulnerabilityLocation
		if res.Start.Col < 1 {
			res.Start.Col = 1
		}
		if res.End.Col < 1 {
			res.End.Col = res.Start.Col
		}

		precise := v.RemediationLocation
		if precise.Start.Line >= res.Start.Line && precise.End.Line <= res.End.Line {
			v.VulnerabilityLocation = precise
			if v.VulnerabilityLocation.Start.Col < 1 {
				v.VulnerabilityLocation.Start.Col = 1
			}
			if v.VulnerabilityLocation.End.Col < 1 {
				v.VulnerabilityLocation.End.Col = v.VulnerabilityLocation.Start.Col
			}
		}
	}
}

func libraryFilesystemSource(ctx context.Context, platform string) *source.FilesystemSource {
	return source.NewFilesystemSource(ctx, []string{"."}, []string{platform}, []string{""}, source.LibrariesDefaultBasePath, false)
}

func regoValidationErrorFromAST(e *ast.Error) RegoValidationError {
	ve := RegoValidationError{
		Code:    e.Code,
		Message: e.Message,
	}
	if e.Location != nil {
		ve.StartLine = e.Location.Row
		ve.StartCol = e.Location.Col
		ve.EndLine = e.Location.Row
		ve.EndCol = e.Location.Col + 1
		if len(e.Location.Text) > 0 {
			ve.EndCol = e.Location.Col + len(e.Location.Text)
		}
	}
	return ve
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
	return libraryFilesystemSource(ctx, s.platform).GetQueryLibrary(ctx, libPlatform)
}
