/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package scan

import (
	"fmt"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// OPA and Regal report accurately but tersely, in the vocabulary of the Rego language
// rather than of a rule author. The functions here rewrite those diagnostics into
// terms an author can act on.
//
// Everything below works from the parsed module or from OPA's own error codes. The one
// exception is findMissingObjectFieldSeparators: OPA's location for a missing comma
// between object fields is often wrong (it may highlight `input` on an earlier line),
// so that case uses a line-structure scan that never inspects string contents.

const (
	datadogPackage    = "package datadog"
	datadogPolicyRule = "DatadogPolicy"
	resultVar         = "result"
)

// Diagnostic codes for problems the scanner detects itself, alongside OPA's rego_* codes.
const (
	codeInvalidPackage     = "invalid_package"
	codeMissingRule        = "missing_rule"
	codeMissingResultField = "missing_result_field"
	codeMissingImport      = "missing_import"
	codeMissingPackage     = "missing_package"
	codeSprintfArity       = "sprintf_arity"
)

// parseMessageRewrites maps OPA parse messages to phrasing that names the likely cause.
// Keyed on exact message text; anything unrecognized passes through untouched.
var parseMessageRewrites = map[string]string{
	"unexpected eof token": "unexpected end of file. Check for an unclosed `{`, `[`, or `(`.",
	"package expected":     "expected `" + datadogPackage + "` at the start of the module.",
}

// enrichParseMessages clarifies OPA's parse errors and, where OPA's location is wrong,
// replaces them with diagnostics derived from the source layout.
func enrichParseMessages(regoContent string, errs []RegoValidationError) []RegoValidationError {
	result := make([]RegoValidationError, 0, len(errs))
	var nonTerminated []RegoValidationError

	for _, e := range errs {
		if e.Code != ast.ParseErr {
			result = append(result, e)
			continue
		}
		switch {
		case parseMessageRewrites[e.Message] != "":
			if e.Message == "package expected" {
				e.Code = codeMissingPackage
			}
			e.Message = parseMessageRewrites[e.Message]
			result = append(result, e)
		case strings.HasPrefix(e.Message, "unexpected }"):
			e.Message = "unexpected `}`. Check for an extra closing brace."
			result = append(result, e)
		case strings.Contains(e.Message, "non-terminated object"):
			// OPA often points at the wrong token (e.g. `input` on an earlier field).
			// A line-structure scan finds the actual missing comma reliably and does not
			// inspect string contents, so it cannot mis-fire on parens inside literals.
			nonTerminated = append(nonTerminated, e)
		default:
			result = append(result, e)
		}
	}

	if len(nonTerminated) > 0 {
		if textErrs := findMissingObjectFieldSeparators(regoContent); len(textErrs) > 0 {
			result = append(result, textErrs...)
		} else if textErrs := findUnclosedParentheses(regoContent); len(textErrs) > 0 {
			result = append(result, textErrs...)
		} else {
			for _, e := range nonTerminated {
				e.Message = "expected `,` before this field, or `}` to close the object."
				result = append(result, e)
			}
		}
	}

	return result
}

// findMissingObjectFieldSeparators reports object fields not followed by `,` or `}`.
// Each diagnostic points at the field key that needs the separator.
func findMissingObjectFieldSeparators(regoContent string) []RegoValidationError {
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

		key := objectFieldKey(cur)
		keyCol := strings.Index(lines[i], `"`)
		if keyCol < 0 {
			keyCol = 0
		}

		msg := "expected ',' or '}' after object field"
		endCol := keyCol + 2
		if key != "" {
			msg = fmt.Sprintf("expected ',' after field %q", key)
			endCol = keyCol + len(key) + 2
		}

		errs = append(errs, RegoValidationError{
			Code:      ast.ParseErr,
			Message:   msg,
			StartLine: i + 1,
			EndLine:   i + 1,
			StartCol:  keyCol + 1,
			EndCol:    endCol + 1,
		})
	}

	return errs
}

func objectFieldKey(line string) string {
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

// findUnclosedParentheses is a fallback when OPA reports a non-terminated object but no
// missing comma is visible — typically a function call missing its closing `)`.
func findUnclosedParentheses(regoContent string) []RegoValidationError {
	var errs []RegoValidationError
	lines := strings.Split(regoContent, "\n")

	for i, text := range lines {
		open, closes := parenBalanceOutsideStrings(text)
		if open <= closes {
			continue
		}
		col, name, ok := unclosedCallOnLine(text)
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

// parenBalanceOutsideStrings counts `(` and `)` outside string literals so parens
// inside quotes or raw strings do not affect unclosed-call detection.
func parenBalanceOutsideStrings(line string) (open, closes int) {
	inRaw, inStr, escaped := false, false, false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if inRaw {
			if ch == '`' {
				inRaw = false
			}
			continue
		}
		if inStr {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inStr = false
			}
			continue
		}
		switch ch {
		case '`':
			inRaw = true
		case '"':
			inStr = true
		case '(':
			open++
		case ')':
			closes++
		}
	}
	return open, closes
}

func unclosedCallOnLine(text string) (col int, name string, ok bool) {
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

// definitions indexes every name the libraries export against the package that defines
// it, so a call to an unimported library can name the exact import to add. Built from
// whatever libraries were loaded, so it covers every platform without a hardcoded list.
func (l regoLibraries) definitions() map[string]string {
	index := make(map[string]string)
	for _, code := range []string{l.common, l.platform} {
		module, err := ast.ParseModuleWithOpts("library.rego", code, ast.ParserOptions{
			RegoVersion: ast.RegoV1,
		})
		if err != nil {
			continue // a broken library is not the author's problem to fix
		}
		path := module.Package.Path.String()
		for _, rule := range module.Rules {
			if name := exportedRuleName(rule); name != "" {
				index[name] = path
			}
		}
	}
	return index
}

func exportedRuleName(rule *ast.Rule) string {
	ref := rule.Head.Ref()
	if len(ref) == 0 {
		return rule.Head.Name.String()
	}
	if name, ok := ref[len(ref)-1].Value.(ast.String); ok {
		return string(name)
	}
	if v, ok := ref[0].Value.(ast.Var); ok {
		return string(v)
	}
	return ""
}

// enrichCompileDiagnostics rewrites OPA compile errors in the author's own vocabulary:
// the alias they wrote rather than the path OPA resolved it to, and the variable name
// rather than Rego's notion of safety.
func enrichCompileDiagnostics(
	module *ast.Module, libDefs map[string]string, errs []RegoValidationError,
) []RegoValidationError {
	aliases := importAliases(module)
	reportedImports := make(map[string]bool)

	out := make([]RegoValidationError, 0, len(errs))
	for _, e := range errs {
		if e.Code == ast.TypeErr {
			alias, importStmt, isMissingImport := missingLibraryImport(e.Message, aliases, libDefs)
			switch {
			case !isMissingImport:
				e.Message = replaceQualifiedPath(e.Message, aliases)
			case reportedImports[alias]:
				continue // one diagnostic per alias, however many calls it has
			default:
				reportedImports[alias] = true
				e.Code = codeMissingImport
				e.Message = fmt.Sprintf("missing import for %q. Add `%s`.", alias, importStmt)
			}
			out = append(out, e)
			continue
		}

		varName, isUnsafe := unsafeVarName(e)
		if !isUnsafe {
			out = append(out, e)
			continue
		}
		// "result is unsafe" only ever follows from an earlier error in the same body.
		if varName == resultVar {
			continue
		}
		if loc, ok := varLocation(module, varName); ok {
			e.StartLine, e.EndLine = loc.Row, loc.Row
			e.StartCol, e.EndCol = loc.Col, loc.Col+len(varName)
		}
		e.Message = fmt.Sprintf("undefined variable %q. Define it before using it.", varName)
		out = append(out, e)
	}
	return out
}

// importAliases maps each import's local alias to the fully qualified path OPA uses in
// error messages.
func importAliases(module *ast.Module) map[string]string {
	aliases := make(map[string]string, len(module.Imports))
	for _, imp := range module.Imports {
		aliases[string(imp.Name())] = imp.Path.String()
	}
	return aliases
}

// missingLibraryImport recognizes "undefined function <alias>.<name>" where the module
// never imports <alias> but some library does export <name> — the author called a
// library helper and forgot the import. It returns the import statement to add, using
// the author's own alias so the suggestion matches what they already wrote.
func missingLibraryImport(
	message string, aliases, libDefs map[string]string,
) (alias, importStmt string, ok bool) {
	const prefix = "undefined function "
	if !strings.HasPrefix(message, prefix) {
		return "", "", false
	}

	ref := strings.TrimPrefix(message, prefix)
	alias, fn, found := strings.Cut(ref, ".")
	if !found || alias == "" {
		return "", "", false
	}
	// An imported alias resolves to a path, so OPA would have reported the path here.
	if _, imported := aliases[alias]; imported {
		return "", "", false
	}

	path, defined := libDefs[fn[strings.LastIndex(fn, ".")+1:]]
	if !defined {
		return "", "", false
	}
	return alias, fmt.Sprintf("import %s as %s", path, alias), true
}

// replaceQualifiedPath rewrites "data.generic.terraform.foo" back to "tf_lib.foo". OPA
// always reports the resolved path, regardless of the alias the author wrote. Longer
// paths are tried first so data.generic.terraform wins over data.generic.
func replaceQualifiedPath(message string, aliases map[string]string) string {
	type aliasPath struct {
		alias string
		path  string
	}
	paths := make([]aliasPath, 0, len(aliases))
	for alias, path := range aliases {
		paths = append(paths, aliasPath{alias, path})
	}
	sort.Slice(paths, func(i, j int) bool {
		return len(paths[i].path) > len(paths[j].path)
	})

	for _, p := range paths {
		if idx := strings.Index(message, p.path+"."); idx >= 0 {
			return message[:idx] + p.alias + message[idx+len(p.path):]
		}
	}
	return message
}

func unsafeVarName(e RegoValidationError) (string, bool) {
	const prefix, suffix = "var ", " is unsafe"
	if e.Code != ast.UnsafeVarErr ||
		!strings.HasPrefix(e.Message, prefix) ||
		!strings.HasSuffix(e.Message, suffix) {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(e.Message, prefix), suffix), true
}

// varLocation finds where a variable is first used. OPA reports unsafe variables against
// the whole expression, which in an editor underlines the entire line.
func varLocation(module *ast.Module, name string) (*ast.Location, bool) {
	var found *ast.Location
	ast.WalkTerms(module, func(term *ast.Term) bool {
		if found != nil {
			return true
		}
		v, ok := term.Value.(ast.Var)
		if !ok || string(v) != name || term.Location == nil {
			return false
		}
		found = term.Location
		return true
	})
	return found, found != nil
}

// dropConsequentialErrors removes compile errors that only exist because of a contract
// violation already reported. A module in the wrong package, or without a DatadogPolicy
// rule, leaves OPA's entrypoint query unresolvable; reporting that as well would bury
// the one problem the author has to fix.
//
// Runs before enrichCompileDiagnostics, so the messages matched here are OPA's own.
func dropConsequentialErrors(contract, compile []RegoValidationError) []RegoValidationError {
	var wrongPackage, missingRule bool
	for _, e := range contract {
		switch e.Code {
		case codeInvalidPackage:
			wrongPackage = true
		case codeMissingRule:
			missingRule = true
		}
	}
	if !wrongPackage && !missingRule {
		return compile
	}

	out := make([]RegoValidationError, 0, len(compile))
	for _, e := range compile {
		if strings.Contains(e.Message, datadogPolicyRule) {
			continue
		}
		out = append(out, e)
	}
	return out
}
