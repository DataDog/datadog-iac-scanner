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
	if errs := ValidateRegoStructure(regoContent); len(errs) > 0 {
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

// ValidateRegoStructure checks package/rule shape and other issues OPA won't flag but that yield zero findings.
func ValidateRegoStructure(regoContent string) []RegoValidationError {
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
			Code: "invalid_package",
			Message: fmt.Sprintf(
				"package must be 'datadog', got %q — the scanner evaluates data.datadog.DatadogPolicy",
				module.Package.Path.String(),
			),
		})
	}

	hasPolicy := false
	for _, rule := range module.Rules {
		if rule.Head.Name == datadogPolicyRule {
			hasPolicy = true
			break
		}
	}
	if !hasPolicy {
		errs = append(errs, RegoValidationError{
			Code: "missing_rule",
			Message: "no '" + datadogPolicyRule + "' rule found — " +
				"the scanner evaluates data.datadog.DatadogPolicy so the rule must use that exact name",
		})
	}

	if len(errs) == 0 {
		errs = append(errs, checkSprintfArity(module)...)
		errs = append(errs, checkResultFields(module)...)
	}

	return errs
}

const datadogPolicyRule = "DatadogPolicy"

var requiredResultFields = []string{
	"documentId",
	"resourceType",
	"resourceName",
	"searchKey",
	"issueType",
	"keyExpectedValue",
	"keyActualValue",
	"searchLine",
}

// checkResultFields reports missing keys in literal result := { ... } assignments.
func checkResultFields(module *ast.Module) []RegoValidationError {
	var errs []RegoValidationError

	ast.WalkRules(module, func(rule *ast.Rule) bool {
		if string(rule.Head.Name) != datadogPolicyRule {
			return false
		}

		ast.WalkExprs(rule, func(expr *ast.Expr) bool {
			if !expr.IsAssignment() {
				return false
			}
			terms, ok := expr.Terms.([]*ast.Term)
			if !ok || len(terms) != 3 {
				return false
			}

			lhs, ok := terms[1].Value.(ast.Var)
			if !ok || string(lhs) != "result" {
				return false
			}

			obj, ok := terms[2].Value.(ast.Object)
			if !ok {
				return false
			}

			present := make(map[string]bool)
			obj.Foreach(func(k, _ *ast.Term) {
				if s, ok := k.Value.(ast.String); ok {
					present[string(s)] = true
				}
			})

			loc := terms[2].Location
			for _, field := range requiredResultFields {
				if !present[field] {
					errs = append(errs, RegoValidationError{
						Code: "missing_result_field",
						Message: fmt.Sprintf(
							"result object is missing required field %q — "+
								"findings without this field will have empty values in scan output",
							field,
						),
						StartLine: loc.Row,
						StartCol:  loc.Col,
						EndLine:   loc.Row,
						EndCol:    loc.Col + 1,
					})
				}
			}
			return false
		})
		return false
	})

	return errs
}

// checkSprintfArity reports sprintf calls where verb count does not match args; OPA misses these at compile time.
func checkSprintfArity(module *ast.Module) []RegoValidationError {
	var errs []RegoValidationError

	ast.WalkTerms(module, func(term *ast.Term) bool {
		call, ok := term.Value.(ast.Call)
		if !ok || len(call) < 3 {
			return false
		}

		ref, ok := call[0].Value.(ast.Ref)
		if !ok || ref.String() != "sprintf" {
			return false
		}

		fmtStr, ok := call[1].Value.(ast.String)
		if !ok {
			return false
		}

		argsArr, ok := call[2].Value.(*ast.Array)
		if !ok {
			return false
		}

		verbCount := countFormatVerbs(string(fmtStr))
		if verbCount != argsArr.Len() {
			loc := term.Location
			errs = append(errs, RegoValidationError{
				Code: "sprintf_arity",
				Message: fmt.Sprintf(
					"sprintf: format string has %d verb(s) but %d argument(s) provided — "+
						"this call returns undefined and the rule body will never unify, producing zero findings",
					verbCount, argsArr.Len(),
				),
				StartLine: loc.Row,
				StartCol:  loc.Col,
				EndLine:   loc.Row,
				EndCol:    loc.Col + 1,
			})
		}
		return false
	})

	return errs
}

func countFormatVerbs(s string) int {
	count := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '%' {
			i++
			if i < len(s) && s[i] != '%' {
				count++
			}
		}
	}
	return count
}

// regoValidationErrorsFrom maps OPA errors to RegoValidationError; ast.Errors is asserted directly because errors.As misses slice types.
func regoValidationErrorsFrom(err error) []RegoValidationError {
	if astErrs, ok := err.(ast.Errors); ok {
		out := make([]RegoValidationError, 0, len(astErrs))
		for _, e := range astErrs {
			out = append(out, regoValidationErrorFromAST(e))
		}
		return out
	}

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
