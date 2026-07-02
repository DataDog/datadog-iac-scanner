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
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/printer"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
)

// RegoValidationError is a compile-time or static-analysis error with source location.
type RegoValidationError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	StartLine int    `json:"start_line"`
	StartCol  int    `json:"start_col"`
	EndLine   int    `json:"end_line"`
	EndCol    int    `json:"end_col"`
}

const (
	scanTargetJSON     = "scan-target.json"
	platformARM        = "azureresourcemanager"
	codeMissingPackage = "missing_package"
	datadogPackage     = "package datadog"
)

// platformTempFileName returns a temp filename whose extension the scanner's file-type
// filter will accept for the given platform.
func platformTempFileName(platform string) string {
	switch strings.ToLower(platform) {
	case "terraform":
		return "scan-target.tf"
	case "cloudformation", platformARM:
		return scanTargetJSON
	case "kubernetes", "ansible":
		return "scan-target.yaml"
	case "dockerfile":
		return "Dockerfile"
	default:
		return scanTargetJSON
	}
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

// ValidateCustomRegoQuery runs three diagnostic phases against regoContent and returns
// all errors in a single call — parse errors, static AST checks, and OPA compilation
// errors are collected independently so no phase gates another:
//
//  1. Parse: syntax errors enriched with precise locations.
//  2. Static checks: package name, rule name, result fields, sprintf arity, missing imports.
//  3. OPA compile against platform libraries: type errors and unresolved references.
//
// Returns (nil, nil) on success, (errors, nil) on validation failure.
func ValidateCustomRegoQuery(
	ctx context.Context,
	platform string,
	regoContent string,
	libSource source.QueriesSource,
) ([]RegoValidationError, error) {
	module, parseErrs := parseRegoModule(regoContent)
	if module == nil {
		if hasPackageExpectedError(parseErrs) {
			if recoveredModule, _ := parseRegoModule(datadogPackage + "\n\n" + regoContent); recoveredModule != nil {
				recoveredErrs := staticChecks(recoveredModule)
				shiftErrorLines(recoveredErrs, -2)
				return append(parseErrs, recoveredErrs...), nil
			}
		}
		return parseErrs, nil
	}

	allErrs := staticChecks(module)

	commonLib, err := libSource.GetQueryLibrary(ctx, "common")
	if err != nil {
		return nil, fmt.Errorf("loading common library: %w", err)
	}

	platformLib, err := libSource.GetQueryLibrary(ctx, source.LibraryName(platform))
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

	if compileErr != nil {
		compileErrs := regoValidationErrorsFrom(compileErr)
		// Filter before enriching: enrichCompileErrors rewrites messages (e.g.
		// "var tf_lib is unsafe" → "undefined variable..."), so isConsequentialCompileError
		// must see the original OPA text to match correctly.
		compileErrs = filterConsequentialCompileErrors(allErrs, compileErrs)
		compileErrs = enrichCompileErrors(regoContent, compileErrs)
		allErrs = append(allErrs, compileErrs...)
	}

	return allErrs, nil
}

// ValidateRegoStructure parses regoContent and runs every static check without loading
// platform libraries — cheaper than ValidateCustomRegoQuery when library compilation
// is not needed. Does not recover from a missing package declaration; use
// ValidateCustomRegoQuery for full user-facing validation.
func ValidateRegoStructure(regoContent string) []RegoValidationError {
	module, parseErrs := parseRegoModule(regoContent)
	if module == nil {
		return parseErrs
	}
	return staticChecks(module)
}

// parseRegoModule parses and enriches parse errors. Returns (module, nil) on success.
func parseRegoModule(regoContent string) (*ast.Module, []RegoValidationError) {
	module, err := ast.ParseModuleWithOpts("query.rego", regoContent, ast.ParserOptions{
		ProcessAnnotation: false,
		RegoVersion:       ast.RegoV1,
	})
	if err != nil {
		return nil, enrichParseErrors(regoContent, regoValidationErrorsFrom(err))
	}
	return module, nil
}

func hasPackageExpectedError(errs []RegoValidationError) bool {
	for _, e := range errs {
		if e.Code == codeMissingPackage {
			return true
		}
	}
	return false
}

func shiftErrorLines(errs []RegoValidationError, delta int) {
	for i := range errs {
		if errs[i].StartLine > 0 {
			errs[i].StartLine = max(1, errs[i].StartLine+delta)
		}
		if errs[i].EndLine > 0 {
			errs[i].EndLine = max(1, errs[i].EndLine+delta)
		}
	}
}

// enrichTypeErrors translates OPA's internal fully-qualified paths in type error
// messages back to the import alias the user wrote. OPA always uses the qualified
// form in errors regardless of how the user wrote it.
func enrichTypeErrors(regoContent string, errs []RegoValidationError) []RegoValidationError {
	aliases := parseImportAliases(regoContent)
	for i := range errs {
		e := &errs[i]
		if e.Code != ast.TypeErr {
			continue
		}
		const prefix = "undefined function "
		if !strings.HasPrefix(e.Message, prefix) {
			continue
		}
		fnFull := strings.TrimPrefix(e.Message, prefix)
		for alias, qualPath := range aliases {
			if strings.HasPrefix(fnFull, qualPath+".") {
				e.Message = prefix + alias + "." + strings.TrimPrefix(fnFull, qualPath+".")
				break
			}
		}
	}
	return errs
}

func enrichCompileErrors(regoContent string, errs []RegoValidationError) []RegoValidationError {
	errs = enrichTypeErrors(regoContent, errs)
	out := make([]RegoValidationError, 0, len(errs))
	for _, e := range errs {
		varName, ok := unsafeVarName(e)
		if !ok {
			out = append(out, e) // not an unsafe-var error; pass through
			continue
		}
		if varName == resultVar {
			continue // "result is unsafe" is always a cascade; skip it
		}
		if line, col, ok := findVariableUsage(regoContent, varName); ok {
			e.StartLine = line
			e.EndLine = line
			e.StartCol = col
			e.EndCol = col + len(varName)
		}
		e.Message = fmt.Sprintf("undefined variable %q. Define it before using it.", varName)
		out = append(out, e)
	}
	return out
}

func unsafeVarName(e RegoValidationError) (string, bool) {
	const prefix = "var "
	const suffix = " is unsafe"
	if e.Code != "rego_unsafe_var_error" ||
		!strings.HasPrefix(e.Message, prefix) ||
		!strings.HasSuffix(e.Message, suffix) {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(e.Message, prefix), suffix), true
}

func findVariableUsage(regoContent, varName string) (line, col int, ok bool) {
	lines := strings.Split(regoContent, "\n")
	for i, text := range lines {
		searchFrom := 0
		for {
			idx := strings.Index(text[searchFrom:], varName)
			if idx < 0 {
				break
			}
			idx += searchFrom
			if isIdentifierBoundary(text, idx-1) && isIdentifierBoundary(text, idx+len(varName)) {
				return i + 1, idx + 1, true
			}
			searchFrom = idx + len(varName)
		}
	}
	return 0, 0, false
}

func isIdentifierBoundary(s string, idx int) bool {
	if idx < 0 || idx >= len(s) {
		return true
	}
	ch := s[idx]
	return (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && ch != '_'
}

const datadogPolicyRule = "DatadogPolicy"

const resultVar = "result"

// staticChecks runs every AST-level check on a successfully parsed module; all checks
// run regardless of what others find.
func staticChecks(module *ast.Module) []RegoValidationError {
	var errs []RegoValidationError

	if module.Package.Path.String() != "data.datadog" {
		e := RegoValidationError{
			Code: "invalid_package",
			Message: fmt.Sprintf(
				"package must be 'datadog', got %q. The scanner evaluates data.datadog.DatadogPolicy.",
				module.Package.Path.String(),
			),
		}
		if loc := module.Package.Location; loc != nil {
			pkgName := strings.TrimPrefix(module.Package.Path.String(), "data.")
			nameCol := loc.Col + len("package ")
			e.StartLine = loc.Row
			e.EndLine = loc.Row
			e.StartCol = nameCol
			e.EndCol = nameCol + len(pkgName)
		}
		errs = append(errs, e)
	}

	hasPolicy := false
	var firstOtherRule *ast.Rule
	for _, rule := range module.Rules {
		if rule.Head.Name == datadogPolicyRule {
			hasPolicy = true
			break
		}
		if firstOtherRule == nil {
			firstOtherRule = rule
		}
	}
	if !hasPolicy {
		e := RegoValidationError{
			Code: "missing_rule",
			Message: "no '" + datadogPolicyRule + "' rule found. " +
				"The scanner evaluates data.datadog.DatadogPolicy so the rule must use that exact name",
		}
		if firstOtherRule != nil && firstOtherRule.Location != nil {
			loc := firstOtherRule.Location
			ruleName := string(firstOtherRule.Head.Name)
			e.StartLine = loc.Row
			e.EndLine = loc.Row
			e.StartCol = loc.Col
			e.EndCol = loc.Col + len(ruleName)
		}
		errs = append(errs, e)
	}

	errs = append(errs, checkMissingImports(module)...)
	errs = append(errs, checkSprintfArity(module)...)
	errs = append(errs, checkResultFields(module)...)

	return errs
}

var requiredResultFields = []string{
	"documentId",
	"resourceType",
	"resourceName",
	"searchKey",
}

var requiredImportAliases = map[string]string{
	"common_lib": "import data.generic.common as common_lib",
	"tf_lib":     "import data.generic.terraform as tf_lib",
}

// parseImportAliases scans regoContent for "import <path> as <alias>" lines and
// returns a map of alias → qualified path. Used to translate OPA's internal paths
// back to the alias the user actually wrote, covering all imported libraries.
func parseImportAliases(regoContent string) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(regoContent, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "import ") {
			continue
		}
		path, alias, ok := strings.Cut(strings.TrimPrefix(line, "import "), " as ")
		if ok {
			out[strings.TrimSpace(alias)] = strings.TrimSpace(path)
		}
	}
	return out
}

func checkMissingImports(module *ast.Module) []RegoValidationError {
	imported := make(map[string]bool, len(module.Imports))
	for _, imp := range module.Imports {
		imported[string(imp.Name())] = true
	}

	reported := make(map[string]bool)
	var errs []RegoValidationError
	ast.WalkTerms(module, func(term *ast.Term) bool {
		ref, ok := term.Value.(ast.Ref)
		if !ok || len(ref) == 0 {
			return false
		}

		alias, ok := ref[0].Value.(ast.Var)
		if !ok {
			return false
		}

		aliasName := string(alias)
		importStmt, required := requiredImportAliases[aliasName]
		if !required || imported[aliasName] || reported[aliasName] {
			return false
		}

		reported[aliasName] = true
		loc := term.Location
		errs = append(errs, RegoValidationError{
			Code:      "missing_import",
			Message:   fmt.Sprintf("missing import for %q. Add `%s`.", aliasName, importStmt),
			StartLine: loc.Row,
			StartCol:  loc.Col,
			EndLine:   loc.Row,
			EndCol:    loc.Col + len(aliasName),
		})
		return false
	})

	return errs
}

// checkResultFields reports missing required keys in literal result := { ... } assignments.
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
			if !ok || string(lhs) != resultVar {
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

			loc := terms[1].Location
			for _, field := range requiredResultFields {
				if !present[field] {
					errs = append(errs, RegoValidationError{
						Code: "missing_result_field",
						Message: fmt.Sprintf(
							"result object is missing required field %q. "+
								"Findings without this field will have empty values in scan output",
							field,
						),
						StartLine: loc.Row,
						StartCol:  loc.Col,
						EndLine:   loc.Row,
						EndCol:    loc.Col + len(string(lhs)),
					})
				}
			}
			return false
		})
		return false
	})

	return errs
}

// checkSprintfArity reports sprintf calls whose verb count does not match the args slice.
// OPA does not catch this at compile time.
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
					"sprintf: format string has %d verb(s) but %d argument(s) provided. "+
						"This call returns undefined and the rule body will never unify, producing zero Findings",
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

// regoValidationErrorsFrom converts OPA errors to RegoValidationError.
// ast.Errors is a slice type that errors.As cannot unwrap, so we assert it directly first.
func regoValidationErrorsFrom(err error) []RegoValidationError {
	var astErrs ast.Errors
	switch e := err.(type) {
	case ast.Errors:
		astErrs = e
	default:
		if !errors.As(err, &astErrs) {
			return []RegoValidationError{{Code: ast.CompileErr, Message: err.Error()}}
		}
	}
	out := make([]RegoValidationError, 0, len(astErrs))
	for _, e := range astErrs {
		out = append(out, regoValidationErrorFromAST(e))
	}
	return out
}

// enrichParseErrors rewrites raw OPA parse messages into actionable diagnostics.
// "non-terminated object" errors are replaced with a text scan that locates every
// missing comma — OPA reports those at the object opener rather than the offending line.
func enrichParseErrors(regoContent string, errs []RegoValidationError) []RegoValidationError {
	result := make([]RegoValidationError, 0, len(errs))
	var nonTerminated []RegoValidationError

	for _, e := range errs {
		switch {
		case e.Code == ast.ParseErr && e.Message == "package expected":
			e.Code = codeMissingPackage
			e.Message = "expected `" + datadogPackage + "` at the start of the module."
			result = append(result, e)
		case e.Code == ast.ParseErr && e.Message == "unexpected identifier token: expected number":
			rewriteMissingInputRoot(regoContent, &e)
			result = append(result, e)
		case e.Code == ast.ParseErr && e.Message == "unexpected eof token":
			e.Message = "unexpected end of file. Check for an unclosed `{`, `[`, or `(`."
			result = append(result, e)
		case e.Code == ast.ParseErr && strings.HasPrefix(e.Message, "unexpected }"):
			e.Message = "unexpected `}`. Check for an extra closing brace."
			result = append(result, e)
		case e.Code == ast.ParseErr && strings.Contains(e.Message, "non-terminated object"):
			nonTerminated = append(nonTerminated, e)
		default:
			result = append(result, e)
		}
	}

	if len(nonTerminated) > 0 {
		textErrs := findAllMissingObjectFieldSeparators(regoContent)
		if len(textErrs) == 0 {
			textErrs = findUnclosedParentheses(regoContent)
		}
		if len(textErrs) > 0 {
			result = append(result, textErrs...)
		} else {
			result = append(result, nonTerminated...) // text scan found nothing; keep OPA originals
		}
	}

	return result
}

// rewriteMissingInputRoot updates err in-place when a bare `.document` reference is
// found. If not found, err is left unchanged and the original OPA message is kept.
func rewriteMissingInputRoot(regoContent string, err *RegoValidationError) {
	line, col, ok := findMissingInputRoot(regoContent)
	if !ok {
		return
	}
	err.Message = "expected `input` before `.document`"
	err.StartLine = line
	err.EndLine = line
	err.StartCol = col
	err.EndCol = col + len(".document")
}

func findMissingInputRoot(regoContent string) (line, col int, ok bool) {
	lines := strings.Split(regoContent, "\n")
	for i, text := range lines {
		idx := strings.Index(text, ".document")
		if idx < 0 {
			continue
		}
		if idx > 0 && !isIdentifierBoundary(text, idx-1) {
			continue
		}
		return i + 1, idx + 1, true
	}
	return 0, 0, false
}

// findAllMissingObjectFieldSeparators scans the source line-by-line and returns a
// diagnostic for every object field that is not followed by a comma when the next line
// starts another field. OPA reports all such cases as a single "non-terminated object"
// at the object opener; this scan localizes each one precisely.
func findAllMissingObjectFieldSeparators(regoContent string) []RegoValidationError {
	var errs []RegoValidationError
	lines := strings.Split(regoContent, "\n")

	for i := 0; i < len(lines)-1; i++ {
		cur := strings.TrimSpace(lines[i])
		next := strings.TrimSpace(lines[i+1])

		if cur == "" || cur == "{" || cur == "}" {
			continue
		}
		if !strings.Contains(cur, `":`) {
			continue
		}
		if strings.HasSuffix(cur, ",") {
			continue
		}
		if !strings.HasPrefix(next, `"`) {
			continue
		}

		key := extractObjectKey(cur)
		keyCol := strings.Index(lines[i], `"`)
		if keyCol < 0 {
			keyCol = 0
		}

		msg := "expected ',' or '}' after object field"
		endCol := keyCol + 2 // at least past the opening quote
		if key != "" {
			msg = fmt.Sprintf("expected ',' after field %q", key)
			endCol = keyCol + len(key) + 2 // "key"
		}

		errs = append(errs, RegoValidationError{
			Code:      ast.ParseErr,
			Message:   msg,
			StartLine: i + 1,
			EndLine:   i + 1,
			StartCol:  keyCol + 1, // 1-indexed
			EndCol:    endCol + 1,
		})
	}

	return errs
}

// findUnclosedParentheses reports lines where '(' outnumber ')', for example a trailing
// comma after sprintf(..., [name], when the closing ')' was removed.
func findUnclosedParentheses(regoContent string) []RegoValidationError {
	var errs []RegoValidationError
	lines := strings.Split(regoContent, "\n")

	for i, text := range lines {
		if strings.Count(text, "(") <= strings.Count(text, ")") {
			continue
		}
		col, name, ok := findUnclosedCallOnLine(text)
		if !ok {
			continue
		}
		endCol := col + 1
		if name != "" {
			endCol = col + len(name)
		}
		errs = append(errs, RegoValidationError{
			Code:      ast.ParseErr,
			Message:   "expected ')' to close function call",
			StartLine: i + 1,
			EndLine:   i + 1,
			StartCol:  col + 1,
			EndCol:    endCol + 1,
		})
	}

	return errs
}

func findUnclosedCallOnLine(text string) (col int, name string, ok bool) {
	lastOpen := strings.LastIndex(text, "(")
	if lastOpen < 0 {
		return 0, "", false
	}

	start := lastOpen - 1
	for start >= 0 && (text[start] == ' ' || text[start] == '\t') {
		start--
	}
	end := start
	for start >= 0 && isIdentChar(text[start]) {
		start--
	}
	if end > start {
		return start + 1, text[start+1 : end+1], true
	}
	return lastOpen, "", true
}

func isIdentChar(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_'
}

func extractObjectKey(line string) string {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, `"`) {
		return ""
	}
	end := strings.Index(trimmed[1:], `"`)
	if end < 0 {
		return ""
	}
	return trimmed[1 : end+1]
}

// filterConsequentialCompileErrors drops OPA compile errors that are direct consequences
// of structural issues we already reported via staticChecks. Showing both would be
// noise, for example "undefined data.datadog.DatadogPolicy" when the user already sees
// invalid_package.
func filterConsequentialCompileErrors(structural, compile []RegoValidationError) []RegoValidationError {
	summary := summarizeStructuralErrors(structural)
	if !summary.hasInvalidPackage && !summary.hasMissingRule && len(summary.missingImportAliases) == 0 {
		return compile
	}

	filtered := make([]RegoValidationError, 0, len(compile))
	for _, e := range compile {
		if isConsequentialCompileError(e, summary) {
			continue
		}
		filtered = append(filtered, e)
	}
	return filtered
}

type structuralErrorSummary struct {
	hasInvalidPackage    bool
	hasMissingRule       bool
	missingImportAliases map[string]bool
}

func summarizeStructuralErrors(errs []RegoValidationError) structuralErrorSummary {
	summary := structuralErrorSummary{missingImportAliases: map[string]bool{}}
	for _, e := range errs {
		switch e.Code {
		case "invalid_package":
			summary.hasInvalidPackage = true
		case "missing_rule":
			summary.hasMissingRule = true
		case "missing_import":
			for alias := range requiredImportAliases {
				if strings.Contains(e.Message, alias) {
					summary.missingImportAliases[alias] = true
				}
			}
		}
	}
	return summary
}

func isConsequentialCompileError(e RegoValidationError, summary structuralErrorSummary) bool {
	if summary.hasInvalidPackage && strings.Contains(e.Message, "data.datadog.DatadogPolicy") {
		return true
	}
	if summary.hasMissingRule && strings.Contains(e.Message, "DatadogPolicy") {
		return true
	}
	for alias := range summary.missingImportAliases {
		if strings.Contains(e.Message, "undefined function "+alias+".") ||
			strings.Contains(e.Message, "var "+alias+" is unsafe") {
			return true
		}
	}
	return false
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
