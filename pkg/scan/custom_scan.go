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
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/platforms"
	"github.com/DataDog/datadog-iac-scanner/pkg/printer"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
)

const scanTargetJSON = "scan-target.json"

// Temp-file names for all supported platforms.
var platformExtensions = map[string]string{
	"Terraform":      "scan-target.tf",
	"CloudFormation": scanTargetJSON,
	"Kubernetes":     "scan-target.yaml",
	"Ansible":        "scan-target.yaml",
	"CICD":           ".github/scan-target.yaml",
	"Dockerfile":     "Dockerfile",
}

// Returns a temp filename for all supported platforms.
func platformTempFileName(platform string) string {
	for _, supported := range platforms.Supported {
		if strings.EqualFold(supported, platform) {
			return platformExtensions[supported]
		}
	}
	return scanTargetJSON
}

// RunCustomRegoQuery writes fileContent to a temp file and runs regoContent against it
// using the same OPA setup as a normal scan.
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

	const ownerReadWritePerm = 0600
	tmpFile := filepath.Join(tmpDir, platformTempFileName(platform))
	if err := os.MkdirAll(filepath.Dir(tmpFile), 0700); err != nil {
		return nil, nil, fmt.Errorf("creating temp file dir: %w", err)
	}

	if err := os.WriteFile(tmpFile, fileContent, ownerReadWritePerm); err != nil {
		return nil, nil, fmt.Errorf("writing temp file: %w", err)
	}

	// LibrariesDefaultBasePath ("./assets/libraries") is CWD-relative; the CLI is
	// always invoked from the repo root so this resolves correctly.
	params := &Parameters{
		Path:                    []string{tmpFile},
		QueriesPath:             []string{"."},
		LibrariesPath:           source.LibrariesDefaultBasePath,
		PreviewLines:            3,
		CloudProvider:           []string{""},
		Platform:                []string{platform},
		ChangedDefaultQueryPath: true,
		MaxFileSizeFlag:         5,
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
	libSource, err := source.NewDatadogSource(datadog.NewDatadogClient())
	if err != nil {
		return nil, nil, fmt.Errorf("creating library source: %w", err)
	}
	c.querySourceFactory = func(_ context.Context, _ []string) (source.QueriesSource, error) {
		return &customRegoSource{platform: platform, regoContent: regoContent, libSource: libSource}, nil
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

// ValidateCustomRegoQuery validates regoContent, returning every diagnostic in a single
// call ordered by source position. Diagnostics come from three sources:
//
//  1. OPA parse — syntax errors.
//  2. Regal — a curated set of Rego bug rules, plus the Datadog contract via embedded rules.
//  3. OPA compile against the platform libraries — type errors, unresolved references,
//     and unsafe built-ins, which only surface with the libraries present.
//
// Messages are rewritten for a rule author's benefit (see rego_messages.go).
//
// A non-empty result means the rule is broken and must not be evaluated.
func ValidateCustomRegoQuery(
	ctx context.Context,
	platform string,
	regoContent string,
	libSource source.QueriesSource,
) ([]RegoValidationError, error) {
	libs, err := loadLibraries(ctx, platform, libSource)
	if err != nil {
		return nil, err
	}

	module, parseErrs := parseRegoModule(regoContent)
	if module == nil {
		return finalizeDiagnostics(
			recoverFromMissingPackage(ctx, regoContent, parseErrs, libs),
		), nil
	}

	return validateParsedModule(ctx, regoContent, module, libs)
}

// ValidateRegoStructure parses regoContent and runs the Datadog contract checks without
// loading platform libraries — cheaper than ValidateCustomRegoQuery when library
// compilation is not needed. Does not recover from a missing package declaration; use
// ValidateCustomRegoQuery for full user-facing validation.
func ValidateRegoStructure(regoContent string) []RegoValidationError {
	module, parseErrs := parseRegoModule(regoContent)
	if module == nil {
		return finalizeDiagnostics(parseErrs)
	}

	contractErrs, err := lintWithRegal(context.Background(), regoContent)
	if err != nil {
		return []RegoValidationError{{Code: ast.CompileErr, Message: err.Error()}}
	}
	return finalizeDiagnostics(contractErrs)
}

func validateParsedModule(
	ctx context.Context, regoContent string, module *ast.Module, libs regoLibraries,
) ([]RegoValidationError, error) {
	contractErrs, err := lintWithRegal(ctx, regoContent)
	if err != nil {
		return nil, err
	}

	compileErrs := compileAgainstLibraries(ctx, regoContent, libs)
	if len(compileErrs) > 0 {
		compileErrs = dropConsequentialErrors(contractErrs, compileErrs)
		compileErrs = enrichCompileDiagnostics(module, libs.definitions(), compileErrs)
	}

	return finalizeDiagnostics(append(contractErrs, compileErrs...)), nil
}

// recoverFromMissingPackage re-runs validation on a synthetically packaged copy so the
// author sees contract and compile problems in the same pass, not just the parse error.
func recoverFromMissingPackage(
	ctx context.Context,
	regoContent string,
	parseErrs []RegoValidationError,
	libs regoLibraries,
) []RegoValidationError {
	if !hasCode(parseErrs, codeMissingPackage) {
		return parseErrs
	}

	const prefix = datadogPackage + "\n\n"
	lineDelta := -strings.Count(prefix, "\n")
	recoveredContent := prefix + regoContent

	recoveredModule, _ := parseRegoModule(recoveredContent)
	if recoveredModule == nil {
		recovered, err := lintWithRegal(ctx, recoveredContent)
		if err != nil {
			return parseErrs
		}
		shiftLines(recovered, lineDelta)
		return append(parseErrs, recovered...)
	}

	recovered, err := validateParsedModule(ctx, recoveredContent, recoveredModule, libs)
	if err != nil {
		return parseErrs
	}
	shiftLines(recovered, lineDelta)
	return append(parseErrs, recovered...)
}

func hasCode(errs []RegoValidationError, code string) bool {
	for _, e := range errs {
		if e.Code == code {
			return true
		}
	}
	return false
}

func shiftLines(errs []RegoValidationError, delta int) {
	for i := range errs {
		if errs[i].StartLine > 0 {
			errs[i].StartLine = max(1, errs[i].StartLine+delta)
		}
		if errs[i].EndLine > 0 {
			errs[i].EndLine = max(1, errs[i].EndLine+delta)
		}
	}
}

// regoLibraries are the only libraries a custom rule can draw on: the shared one and
// the one for the platform being validated.
type regoLibraries struct {
	common   string
	platform string
}

func loadLibraries(
	ctx context.Context, platform string, libSource source.QueriesSource,
) (regoLibraries, error) {
	commonLib, err := libSource.GetQueryLibrary(ctx, "common")
	if err != nil {
		return regoLibraries{}, fmt.Errorf("loading common library: %w", err)
	}

	platformLib, err := libSource.GetQueryLibrary(ctx, source.LibraryName(platform))
	if err != nil {
		return regoLibraries{}, fmt.Errorf("loading platform library: %w", err)
	}

	return regoLibraries{common: commonLib.LibraryCode, platform: platformLib.LibraryCode}, nil
}

// compileAgainstLibraries compiles regoContent together with the platform libraries
// using the same OPA setup as a real scan.
func compileAgainstLibraries(ctx context.Context, regoContent string, libs regoLibraries) []RegoValidationError {
	_, compileErr := rego.New(
		rego.Query(utils.RegoQuery),
		rego.SetRegoVersion(ast.RegoV1),
		rego.Module("Common", libs.common),
		rego.Module("Generic", libs.platform),
		rego.Module(customRuleFileName, regoContent),
		rego.UnsafeBuiltins(map[string]struct{}{
			"http.send":   {},
			"opa.runtime": {},
		}),
	).PrepareForEval(ctx)

	if compileErr == nil {
		return nil
	}
	return regoValidationErrorsFrom(compileErr)
}

// parseRegoModule parses regoContent, returning (module, nil) on success and
// (nil, diagnostics) on failure.
func parseRegoModule(regoContent string) (*ast.Module, []RegoValidationError) {
	module, err := ast.ParseModuleWithOpts(customRuleFileName, regoContent, ast.ParserOptions{
		ProcessAnnotation: false,
		RegoVersion:       ast.RegoV1,
	})
	if err != nil {
		return nil, enrichParseMessages(regoContent, regoValidationErrorsFrom(err))
	}
	return module, nil
}

func clampLocation(loc *model.ResourceLocation) {
	loc.Start.Col = max(loc.Start.Col, 1)
	if loc.End.Col < 1 {
		loc.End.Col = loc.Start.Col
	}
}

func narrowToAttributeLocation(vulns []model.Vulnerability) {
	for i := range vulns {
		v := &vulns[i]
		clampLocation(&v.VulnerabilityLocation)
		precise := v.RemediationLocation
		if precise.Start.Line >= v.VulnerabilityLocation.Start.Line &&
			precise.End.Line <= v.VulnerabilityLocation.End.Line {
			v.VulnerabilityLocation = precise
			clampLocation(&v.VulnerabilityLocation)
		}
	}
}

// customRegoSource is an in-memory QueriesSource that injects a single custom Rego rule.
type customRegoSource struct {
	platform    string
	regoContent string
	libSource   source.QueriesSource
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
			},
			Aggregation: 1,
		},
	}, nil
}

func (s *customRegoSource) GetQueryLibrary(ctx context.Context, libPlatform string) (source.RegoLibraries, error) {
	return s.libSource.GetQueryLibrary(ctx, source.LibraryName(libPlatform))
}
