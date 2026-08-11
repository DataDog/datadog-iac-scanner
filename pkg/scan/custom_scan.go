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
	"regexp"
	"sort"
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
	codeMissingPackage = "missing_package"
	codeMissingImport  = "missing_import"
	codeUnsafeVarError = "rego_unsafe_var_error"
	datadogPackage     = "package datadog"
)

// Temp-file names for all supported platforms.
var platformExtensions = map[string]string{
	"Terraform":      "scan-target.tf",
	"CloudFormation": scanTargetJSON,
	"Kubernetes":     "scan-target.yaml",
	"Ansible":        "scan-target.yaml",
	"CICD":           "scan-target.yaml",
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
//  2. Static checks: package name, rule name, result fields, sprintf arity.
//  3. OPA compile against platform libraries: type errors, unresolved references, and
//     missing imports (detected from the library's real content, not a hardcoded table).
//
// When the package declaration is missing, the module is still parsed and run through
// phases 2 and 3 against a recovered copy (with `package datadog` prepended) so a
// single call surfaces every other problem too, not just the missing package.
//
// Returns (nil, nil) on success, (errors, nil) on validation failure.
func ValidateCustomRegoQuery(
	ctx context.Context,
	platform string,
	regoContent string,
	libSource source.QueriesSource,
) ([]RegoValidationError, error) {
	module, parseErrs := parseRegoModule(regoContent)
	compileContent := regoContent
	lineOffset := 0

	if module == nil {
		if !hasPackageExpectedError(parseErrs) {
			return parseErrs, nil
		}
		compileContent = datadogPackage + "\n\n" + regoContent
		recovered, _ := parseRegoModule(compileContent)
		if recovered == nil {
			return parseErrs, nil
		}
		module = recovered
		lineOffset = -2
	}

	allErrs := staticChecks(module)
	shiftErrorLines(allErrs, lineOffset)

	commonLib, err := libSource.GetQueryLibrary(ctx, "common")
	if err != nil {
		return nil, fmt.Errorf("loading common library: %w", err)
	}

	platformLib, err := libSource.GetQueryLibrary(ctx, source.LibraryName(platform))
	if err != nil {
		return nil, fmt.Errorf("loading platform library: %w", err)
	}

	if compileErrs := compileCustomRego(ctx, compileContent, commonLib.LibraryCode, platformLib.LibraryCode); compileErrs != nil {
		libs := []libraryInfo{parseLibrary(commonLib.LibraryCode), parseLibrary(platformLib.LibraryCode)}
		// Filter before enriching: isConsequentialCompileError must see the original OPA
		// text — enrichCompileErrors rewrites messages (e.g. "var tf_lib is unsafe" →
		// "missing_import"), which would no longer match.
		compileErrs = filterConsequentialCompileErrors(allErrs, compileErrs)
		compileErrs = enrichCompileErrors(module, compileContent, libs, compileErrs)
		shiftErrorLines(compileErrs, lineOffset)
		allErrs = append(allErrs, compileErrs...)
	}

	allErrs = append(parseErrs, allErrs...)
	sortRegoValidationErrors(allErrs)
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
	errs := staticChecks(module)
	sortRegoValidationErrors(errs)
	return errs
}

// compileCustomRego compiles regoContent against the given library sources using the
// same OPA setup as a real scan, returning the resulting errors (nil on success).
func compileCustomRego(ctx context.Context, regoContent, commonLibCode, platformLibCode string) []RegoValidationError {
	_, err := rego.New(
		rego.Query(utils.RegoQuery),
		rego.SetRegoVersion(ast.RegoV1),
		rego.Module("Common", commonLibCode),
		rego.Module("Generic", platformLibCode),
		rego.Module("query.rego", regoContent),
		rego.UnsafeBuiltins(map[string]struct{}{
			"http.send":   {},
			"opa.runtime": {},
		}),
	).PrepareForEval(ctx)
	if err == nil {
		return nil
	}
	return regoValidationErrorsFrom(err)
}

// parseRegoModule parses and enriches parse errors. Returns (module, nil) on success.
func parseRegoModule(regoContent string) (*ast.Module, []RegoValidationError) {
	module, err := ast.ParseModuleWithOpts("query.rego", regoContent, ast.ParserOptions{
		ProcessAnnotation: false,
		RegoVersion:       ast.RegoV1,
	})
	if err != nil {
		errs := enrichParseErrors(regoContent, regoValidationErrorsFrom(err))
		sortRegoValidationErrors(errs)
		return nil, errs
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
	if delta == 0 {
		return
	}
	for i := range errs {
		if errs[i].StartLine > 0 {
			errs[i].StartLine = max(1, errs[i].StartLine+delta)
		}
		if errs[i].EndLine > 0 {
			errs[i].EndLine = max(1, errs[i].EndLine+delta)
		}
	}
}

func sortRegoValidationErrors(errs []RegoValidationError) {
	sort.SliceStable(errs, func(i, j int) bool {
		if errs[i].StartLine != errs[j].StartLine {
			return errs[i].StartLine < errs[j].StartLine
		}
		return errs[i].StartCol < errs[j].StartCol
	})
}

// moduleImportAliases returns every import in module keyed by the local alias it is
// bound to (explicit "as", or the default alias when omitted), mapped to the
// fully-qualified path it refers to, e.g. "tf_lib" -> "data.generic.terraform".
func moduleImportAliases(module *ast.Module) map[string]string {
	out := make(map[string]string, len(module.Imports))
	for _, imp := range module.Imports {
		var path string
		switch v := imp.Path.Value.(type) {
		case ast.Ref:
			path = v.String()
		case ast.Var:
			path = string(v)
		default:
			continue
		}
		out[string(imp.Name())] = path
	}
	return out
}

func declaredAliasSet(module *ast.Module) map[string]bool {
	declared := make(map[string]bool, len(module.Imports))
	for _, imp := range module.Imports {
		declared[string(imp.Name())] = true
	}
	return declared
}

// translateQualifiedPaths rewrites every fully-qualified library path (e.g.
// "data.generic.terraform") appearing in a compile error's message back to the alias
// the user actually imported it under. OPA always reports the canonical qualified form
// regardless of how the module referenced it; left alone this leaks internal package
// layout into user-facing diagnostics. Applied to every message rather than one
// specific phrasing, so it also fixes "undefined ref", "arity mismatch", and other
// message shapes that embed a qualified path, not just "undefined function ...".
func translateQualifiedPaths(module *ast.Module, errs []RegoValidationError) []RegoValidationError {
	aliases := moduleImportAliases(module)
	if len(aliases) == 0 {
		return errs
	}

	type aliasPath struct{ path, alias string }
	pairs := make([]aliasPath, 0, len(aliases))
	for alias, path := range aliases {
		pairs = append(pairs, aliasPath{path, alias})
	}
	// Longest path first so a nested library path is never partially shadowed by a
	// shorter one that happens to be a prefix of it.
	sort.Slice(pairs, func(i, j int) bool { return len(pairs[i].path) > len(pairs[j].path) })

	for i := range errs {
		for _, p := range pairs {
			errs[i].Message = strings.ReplaceAll(errs[i].Message, p.path+".", p.alias+".")
		}
	}
	return errs
}

// libraryInfo pairs a Rego library's canonical package path with the set of function
// (rule) names it declares. Built directly from the library's own source so import
// suggestions stay correct for every platform without a hardcoded alias table.
type libraryInfo struct {
	path      string
	functions map[string]bool
}

func parseLibrary(libCode string) libraryInfo {
	info := libraryInfo{functions: map[string]bool{}}
	module, err := ast.ParseModuleWithOpts("library.rego", libCode, ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		return info
	}
	info.path = module.Package.Path.String()
	for _, rule := range module.Rules {
		info.functions[string(rule.Head.Name)] = true
	}
	return info
}

func findLibraryDefining(libs []libraryInfo, fn string) string {
	for _, lib := range libs {
		if lib.functions[fn] {
			return lib.path
		}
	}
	return ""
}

func enrichCompileErrors(module *ast.Module, regoContent string, libs []libraryInfo, errs []RegoValidationError) []RegoValidationError {
	declared := declaredAliasSet(module)

	out := make([]RegoValidationError, 0, len(errs))
	missingAliases := make(map[string]bool)
	for _, e := range errs {
		if e.Code == ast.TypeErr && strings.HasPrefix(e.Message, "undefined function ") {
			rewritten, alias := rewriteUndefinedFunction(e, libs)
			if alias != "" {
				missingAliases[alias] = true
			}
			out = append(out, rewritten)
			continue
		}

		varName, ok := unsafeVarName(e)
		if !ok {
			out = append(out, e) // not an unsafe-var error; pass through
			continue
		}
		if varName == resultVar {
			continue // "result is unsafe" is always a cascade; skip it
		}
		rewritten := rewriteUnsafeVar(e, varName, regoContent, declared, libs)
		if rewritten.Code == codeMissingImport {
			missingAliases[varName] = true
		}
		out = append(out, rewritten)
	}

	// A variable bound from an expression that itself references a now-identified
	// missing import (e.g. `name := k8s_lib.get_pod_name`) is also reported unsafe by
	// OPA as a pure consequence — drop that cascade once its root cause is known.
	out = dropImportCascades(out, missingAliases, regoContent)

	// Runs last: covers every remaining message shape that still embeds a qualified
	// library path (e.g. "undefined ref", "arity mismatch") once the two more specific
	// rewrites above have handled "undefined function" and "unsafe var".
	return translateQualifiedPaths(module, out)
}

func dropImportCascades(errs []RegoValidationError, missingAliases map[string]bool, regoContent string) []RegoValidationError {
	if len(missingAliases) == 0 {
		return errs
	}
	lines := strings.Split(regoContent, "\n")

	out := make([]RegoValidationError, 0, len(errs))
	for _, e := range errs {
		if e.Code == codeUnsafeVarError && e.StartLine >= 1 && e.StartLine <= len(lines) {
			varName, ok := unsafeVarFromError(e)
			if ok && isImportCascadeVar(lines[e.StartLine-1], varName, missingAliases) {
				continue
			}
		}
		out = append(out, e)
	}
	return out
}

// unsafeVarFromError extracts the variable name from an unsafe-var diagnostic, whether
// OPA's original message or our rewritten "undefined variable" form.
func unsafeVarFromError(e RegoValidationError) (string, bool) {
	if name, ok := unsafeVarName(e); ok {
		return name, true
	}
	const prefix = `undefined variable "`
	const suffix = `". Define it before using it.`
	if strings.HasPrefix(e.Message, prefix) && strings.HasSuffix(e.Message, suffix) {
		return strings.TrimSuffix(strings.TrimPrefix(e.Message, prefix), suffix), true
	}
	return "", false
}

// isImportCascadeVar reports whether varName is bound via := from an expression that
// references a missing import alias — e.g. suppress `name` for `name := k8s_lib.fn`
// but not `podd` on `name := [k8s_lib.fn, podd]`.
func isImportCascadeVar(line, varName string, missingAliases map[string]bool) bool {
	rhs, ok := findAssignmentRHS(line, varName)
	if !ok {
		return false
	}
	for alias := range missingAliases {
		if referencesIdentifier(rhs, alias) {
			return true
		}
	}
	return false
}

func findAssignmentRHS(line, varName string) (string, bool) {
	searchFrom := 0
	for {
		idx := strings.Index(line[searchFrom:], varName)
		if idx < 0 {
			return "", false
		}
		idx += searchFrom
		if !isIdentifierBoundary(line, idx-1) || !isIdentifierBoundary(line, idx+len(varName)) {
			searchFrom = idx + len(varName)
			continue
		}
		after := idx + len(varName)
		for after < len(line) && (line[after] == ' ' || line[after] == '\t') {
			after++
		}
		if after+1 < len(line) && line[after:after+2] == ":=" {
			return strings.TrimSpace(line[after+2:]), true
		}
		searchFrom = idx + len(varName)
	}
}

func referencesIdentifier(text, name string) bool {
	searchFrom := 0
	for {
		idx := strings.Index(text[searchFrom:], name)
		if idx < 0 {
			return false
		}
		idx += searchFrom
		if isIdentifierBoundary(text, idx-1) && isIdentifierBoundary(text, idx+len(name)) {
			return true
		}
		searchFrom = idx + len(name)
	}
}

// rewriteUndefinedFunction handles OPA's "undefined function X" compile error. When X
// is already a fully-qualified path (starts with "data."), the alias itself resolved
// fine and this is a genuine typo of a function that doesn't exist in that library —
// left as-is for translateQualifiedPaths to convert back to the user's alias. When X is
// NOT qualified (e.g. "tf_lib.resolve_s3_bucket_name"), the alias never resolved at all
// because it was never imported; this is the missing-import case, and the exact library
// to suggest is found by checking which one actually declares the called function.
// Returns the rewritten error, plus the missing-import alias (empty when it didn't
// identify one) so the caller can suppress dependent cascades.
func rewriteUndefinedFunction(e RegoValidationError, libs []libraryInfo) (rewritten RegoValidationError, missingAlias string) {
	const prefix = "undefined function "
	fnFull := strings.TrimPrefix(e.Message, prefix)
	if strings.HasPrefix(fnFull, "data.") {
		return e, ""
	}

	alias, fn, ok := strings.Cut(fnFull, ".")
	if !ok {
		return e, ""
	}
	libPath := findLibraryDefining(libs, fn)
	if libPath == "" {
		return e, ""
	}
	e.Code = codeMissingImport
	e.Message = fmt.Sprintf(
		"%q is not imported. Add `import %s as %s` to use %s.%s(...).",
		alias, libPath, alias, alias, fn,
	)
	return e, alias
}

// rewriteUnsafeVar turns a raw "var X is unsafe" compiler error into an actionable
// diagnostic. If X is referenced like a library alias (X.someFunc(...), but as a plain
// reference rather than a call — the call form is caught earlier by
// rewriteUndefinedFunction) and someFunc is actually declared in one of the platform's
// libraries, this points precisely at the missing import for any platform, since it is
// derived from the library's real content rather than a hardcoded per-platform alias
// table. Otherwise it is a genuine undefined variable, so a generic message is used.
func rewriteUnsafeVar(
	e RegoValidationError,
	varName, regoContent string,
	declared map[string]bool,
	libs []libraryInfo,
) RegoValidationError {
	e = narrowUnsafeVarLocation(e, varName, regoContent)

	if !declared[varName] {
		if fn, ok := findDottedCallAt(regoContent, e.StartLine, varName); ok {
			if libPath := findLibraryDefining(libs, fn); libPath != "" {
				e.Code = codeMissingImport
				e.Message = fmt.Sprintf(
					"%q is not imported. Add `import %s as %s` to use %s.%s(...).",
					varName, libPath, varName, varName, fn,
				)
				return e
			}
		}
	}

	e.Message = fmt.Sprintf("undefined variable %q. Define it before using it.", varName)
	return e
}

// narrowUnsafeVarLocation tightens an unsafe-var error's span from the whole expression
// OPA attaches it to (e.g. the full "resource.acl == \"public-read\"" condition) down to
// just the offending identifier. OPA's row is always trusted — it already points at the
// variable's earliest real usage — only the column span is refined, and only a full-file
// scan is used as a fallback on the rare chance the identifier isn't found on that exact
// line (e.g. a multi-line expression) or OPA attached no location at all.
func narrowUnsafeVarLocation(e RegoValidationError, varName, regoContent string) RegoValidationError {
	lines := strings.Split(regoContent, "\n")
	if e.StartLine >= 1 && e.StartLine <= len(lines) {
		if col, ok := findIdentifierInLine(lines[e.StartLine-1], varName); ok {
			e.StartCol = col
			e.EndLine = e.StartLine
			e.EndCol = col + len(varName)
			return e
		}
	}
	if line, col, ok := findVariableUsage(regoContent, varName); ok {
		e.StartLine, e.EndLine = line, line
		e.StartCol, e.EndCol = col, col+len(varName)
	}
	return e
}

func findIdentifierInLine(text, varName string) (col int, ok bool) {
	searchFrom := 0
	for {
		idx := strings.Index(text[searchFrom:], varName)
		if idx < 0 {
			return 0, false
		}
		idx += searchFrom
		if isIdentifierBoundary(text, idx-1) && isIdentifierBoundary(text, idx+len(varName)) {
			return idx + 1, true
		}
		searchFrom = idx + len(varName)
	}
}

func unsafeVarName(e RegoValidationError) (string, bool) {
	const prefix = "var "
	const suffix = " is unsafe"
	if e.Code != codeUnsafeVarError ||
		!strings.HasPrefix(e.Message, prefix) ||
		!strings.HasSuffix(e.Message, suffix) {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(e.Message, prefix), suffix), true
}

var identifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*`)

// findDottedCallAt looks for "<alias>.<name>" on the line the compiler flagged first,
// falling back to a whole-file scan so a multi-line expression still resolves.
func findDottedCallAt(regoContent string, line int, alias string) (string, bool) {
	lines := strings.Split(regoContent, "\n")
	if line >= 1 && line <= len(lines) {
		if fn, ok := findDottedCallInText(lines[line-1], alias); ok {
			return fn, true
		}
	}
	for _, text := range lines {
		if fn, ok := findDottedCallInText(text, alias); ok {
			return fn, true
		}
	}
	return "", false
}

func findDottedCallInText(text, alias string) (string, bool) {
	needle := alias + "."
	searchFrom := 0
	for {
		idx := strings.Index(text[searchFrom:], needle)
		if idx < 0 {
			return "", false
		}
		idx += searchFrom
		if isIdentifierBoundary(text, idx-1) {
			if m := identifierPattern.FindString(text[idx+len(needle):]); m != "" {
				return m, true
			}
		}
		searchFrom = idx + len(needle)
	}
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
		// Fall back to the package declaration's location when the module has no rules
		// at all, so this diagnostic always carries a valid (non-zero) position.
		loc := module.Package.Location
		nameLen := 1
		if firstOtherRule != nil && firstOtherRule.Location != nil {
			loc = firstOtherRule.Location
			nameLen = len(string(firstOtherRule.Head.Name))
		}
		if loc != nil {
			e.StartLine = loc.Row
			e.EndLine = loc.Row
			e.StartCol = loc.Col
			e.EndCol = loc.Col + nameLen
		}
		errs = append(errs, e)
	}

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
// missing comma and every unclosed call — OPA reports those at the object opener
// rather than the offending line, and (unlike OPA) both classes are searched for and
// reported together so a file with both bug types doesn't only show one.
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
		var textErrs []RegoValidationError
		textErrs = append(textErrs, findAllMissingObjectFieldSeparators(regoContent)...)
		textErrs = append(textErrs, findUnclosedParentheses(regoContent)...)
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
		open, closing := countParensOutsideStrings(text)
		if open <= closing {
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

func countParensOutsideStrings(text string) (open, closing int) {
	inString := false
	escaped := false
	for i := 0; i < len(text); i++ {
		ch := text[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inString = false
			}
			continue
		}
		if ch == '#' {
			break
		}
		if ch == '"' {
			inString = true
			continue
		}
		switch ch {
		case '(':
			open++
		case ')':
			closing++
		}
	}
	return open, closing
}

func findUnclosedCallOnLine(text string) (col int, name string, ok bool) {
	lastOpen := lastOpenParenOutsideStrings(text)
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

func lastOpenParenOutsideStrings(text string) int {
	inString := false
	escaped := false
	last := -1
	for i := 0; i < len(text); i++ {
		ch := text[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inString = false
			}
			continue
		}
		if ch == '#' {
			break
		}
		if ch == '"' {
			inString = true
			continue
		}
		if ch == '(' {
			last = i
		}
	}
	return last
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
	if !summary.hasInvalidPackage && !summary.hasMissingRule {
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
	hasInvalidPackage bool
	hasMissingRule    bool
}

func summarizeStructuralErrors(errs []RegoValidationError) structuralErrorSummary {
	var summary structuralErrorSummary
	for _, e := range errs {
		switch e.Code {
		case "invalid_package":
			summary.hasInvalidPackage = true
		case "missing_rule":
			summary.hasMissingRule = true
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
