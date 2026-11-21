package docker

import (
	"maps"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/moby/buildkit/frontend/dockerfile/shell"
)

// Instruction names, lowercased as in Command.Cmd.
const (
	fromInstruction = "from"
	argInstruction  = "arg"
	envInstruction  = "env"
	runInstruction  = "run"
)

// shellEscapeToken is the escape character of the POSIX shell that runs RUN, CMD, ENTRYPOINT and
// HEALTHCHECK text, used to delimit its ${NAME<modifier>...} references. The `# escape=` directive does not change it.
// Windows images run that text with cmd by default, where `$NAME` is not a reference at all; it is still read as POSIX
// shell text.
const shellEscapeToken = '\\'

// shellSyntax reads the RUN, CMD, ENTRYPOINT and HEALTHCHECK arguments, in shell form and in exec form. Docker does
// not expand them: a shell does, at run time, possibly a nested one (`sh -c '... "$URL"'`, `env bash -c ...`, a script
// passed as an argument). Without a shell parser, every reference to a known name is substituted, inside quotes and
// after escapes too: tracking quotes loses references after nested quotes such as `"$(printf '"')"`. The cost is that
// a reference that stays literal is substituted too: `curl '$MIRROR/x'`, or `["curl", "$M/x"]` where curl receives
// `$M/x`. When a ${NAME<modifier>...} cannot be computed, the references inside it are still substituted
// (`${MIRROR:-$URL}` with MIRROR unknown, `${MIRROR:=$URL}`, which BuildKit's lexer does not support).
var shellSyntax = referenceSyntax{
	escapeToken: shellEscapeToken, nameLength: shellNameLength, substituteUnresolvedOperands: true,
	doubleDollarIsEscapedDollar: true,
}

// dockerExpandedInstructions are the instructions whose arguments Docker expands itself ("Environment replacement"
// in the Dockerfile reference). FROM (which only sees the global ARGs), ENV (declareEnvs) and ARG (declareArgs) are
// handled apart; ARG is listed for ONBUILD ARG triggers.
var dockerExpandedInstructions = map[string]bool{
	argInstruction: true, "add": true, "copy": true, "workdir": true, "user": true,
	"expose": true, "label": true, "volume": true, "stopsignal": true,
}

// runtimeShellInstructions run in the container, with the image configuration environment.
var runtimeShellInstructions = map[string]bool{"cmd": true, "entrypoint": true, "healthcheck": true}

// expandedFlagPrefixes are the ADD/COPY flags whose values BuildKit expands (AddCommand.Expand, CopyCommand.Expand).
var expandedFlagPrefixes = []string{"--chown=", "--chmod=", "--checksum="}

// stageScope holds the variables known at one point of a build stage. A variable that is absent is unknown: it was
// never declared, it is an ARG without a value, or it comes from the base image or from --build-arg.
type stageScope struct {
	// buildEnv is what RUN and the instructions Docker expands see: ARG and ENV values, the last write wins.
	buildEnv scopeEnv
	// imageEnv is the image configuration environment: ENV values only. CMD, ENTRYPOINT, HEALTHCHECK and ONBUILD
	// triggers run with it.
	imageEnv scopeEnv
	// argValues are the buildEnv entries last written by an ARG. They are the only values substituted in ENV
	// instructions (see declareEnvs).
	argValues scopeEnv
}

func newStageScope() *stageScope {
	return &stageScope{buildEnv: scopeEnv{}, imageEnv: scopeEnv{}, argValues: scopeEnv{}}
}

// setArg records an ARG value, or makes name unknown when known is false.
func (s *stageScope) setArg(name string, value scopeValue, known bool) {
	s.buildEnv.set(name, value, known)
	s.argValues.set(name, value, known)
}

// setEnv records an ENV value, or makes name unknown when known is false.
func (s *stageScope) setEnv(name string, value scopeValue, known bool) {
	s.buildEnv.set(name, value, known)
	s.imageEnv.set(name, value, known)
	delete(s.argValues, name)
}

// variableResolver substitutes ARG and ENV references in the commands of one Dockerfile, in file order.
type variableResolver struct {
	escapeToken rune
	// dockerfileSyntax reads the instructions Docker expands itself, with the file's escape token.
	dockerfileSyntax referenceSyntax
	globalArgs       scopeEnv
	// stages maps each stage alias (lowercased, as BuildKit does) to the scope of that stage.
	stages map[string]*stageScope
	// current is the scope of the current stage, nil before the first FROM.
	current *stageScope
}

func newVariableResolver(escapeToken rune) *variableResolver {
	return &variableResolver{
		escapeToken:      escapeToken,
		dockerfileSyntax: referenceSyntax{escapeToken: byte(escapeToken), quoted: true, nameLength: dockerfileNameLength},
		globalArgs:       scopeEnv{},
		stages:           make(map[string]*stageScope),
	}
}

// resolve substitutes the references in cmd.Value (and in the expanded ADD/COPY flags) with the values in scope, then
// records the variables that cmd declares. Only references are replaced: quotes and the rest of the text are kept.
func (r *variableResolver) resolve(cmd *Command) {
	switch {
	case cmd.Cmd == fromInstruction:
		r.startStage(cmd.Value)
		r.substituteValues(cmd.Value, r.globalArgs, r.dockerfileSyntax)
	case cmd.Cmd == argInstruction:
		r.declareArgs(cmd.Value)
	case r.current == nil:
		// Docker only accepts ARG before the first FROM.
	case cmd.Cmd == envInstruction:
		r.declareEnvs(cmd.Value)
	case cmd.Cmd == "onbuild":
		// The trigger runs in a later build, after FROM, with the image configuration environment, which only holds
		// ENV values. It does not change the scope of this stage. ONBUILD ENV keeps its references, like ENV.
		// Limitation: the trigger is substituted with the image environment at declaration time. BuildKit runs it in
		// the derived build, after the triggers declared before it (`ONBUILD ENV OWNER=root` then
		// `ONBUILD USER $OWNER`), and the triggers do not change the scope of a stage built FROM this one.
		if cmd.SubCmd != envInstruction {
			r.substituteInstruction(cmd.SubCmd, cmd.Value, r.current.imageEnv)
		}
	default:
		r.substituteInstruction(cmd.Cmd, cmd.Value, r.current.buildEnv)
		if cmd.Cmd == "add" || cmd.Cmd == "copy" {
			r.substituteFlags(cmd.Flags, r.current.buildEnv)
		}
	}
}

// substituteInstruction substitutes the values of an instruction other than FROM, ARG and ENV.
// scope is the build environment, or the image configuration environment for an ONBUILD trigger.
func (r *variableResolver) substituteInstruction(instruction string, values []string, scope scopeEnv) {
	switch {
	case dockerExpandedInstructions[instruction]:
		r.substituteValues(values, scope, r.dockerfileSyntax)
	case instruction == runInstruction:
		r.substituteValues(values, scope, shellSyntax)
	case runtimeShellInstructions[instruction]:
		r.substituteValues(values, r.current.imageEnv, shellSyntax)
	}
}

// startStage resets the scope at a FROM line. A stage built on an earlier stage inherits its ARG and ENV values:
// BuildKit copies the base stage state and build args (dockerfile2llb/convert.go, dispatchState.init:
// `ds.state = ds.base.state` and `ds.buildArgs = append(ds.buildArgs, ds.base.buildArgs...)`).
func (r *variableResolver) startStage(fromValues []string) {
	r.current = newStageScope()
	if len(fromValues) == 0 {
		return
	}
	// BuildKit expands the base name with the global ARGs before looking up the stage names.
	baseName := strings.ToLower(r.expandValue(fromValues[0], r.globalArgs))
	if base, ok := r.stages[baseName]; ok {
		maps.Copy(r.current.buildEnv, base.buildEnv)
		maps.Copy(r.current.imageEnv, base.imageEnv)
		maps.Copy(r.current.argValues, base.argValues)
	}
	if len(fromValues) == 3 && strings.EqualFold(fromValues[1], "as") {
		r.stages[strings.ToLower(fromValues[2])] = r.current
	}
}

// declareArgs handles `ARG name[=default] ...`, before the first FROM (global ARGs, only visible to FROM lines and to
// ARG redeclarations in a stage) or in a stage. Each ARG sees the ARGs declared before it, in the same instruction
// too. Inside a stage, an ARG without a default takes the value of the global ARG of the same name, if it has one.
func (r *variableResolver) declareArgs(values []string) {
	scope := r.globalArgs
	if r.current != nil {
		scope = r.current.buildEnv
	}
	for i, value := range values {
		values[i] = substituteReferences(value, scope, r.dockerfileSyntax)
		name, defaultValue, hasDefault := strings.Cut(value, "=")
		var argValue scopeValue
		known := false
		switch {
		case hasDefault:
			argValue, known = r.tryExpandValue(defaultValue, scope)
		case r.current == nil:
			continue
		default:
			if argValue, known = r.globalArgs[name]; !known {
				continue
			}
		}
		if r.current == nil {
			r.globalArgs.set(name, argValue, known)
		} else {
			r.current.setArg(name, argValue, known)
		}
	}
}

// declareEnvs handles `ENV name=value ...`, whose values come as (name, value, separator) triples. Every name and
// value is expanded with the variables in scope before the instruction, as Docker does (EnvCommand.Expand), so
// `ENV $KEY=root` declares the variable named by KEY.
//
// In the ENV instruction itself, only references to ARG values are substituted, as before stage scoping existed.
// References to ENV variables stay as written, unlike Docker: rules such as "ENV refers to itself" (hadolint DL3044)
// read them, while `ENV VERSION=${VERSION}` still shows the value of `ARG VERSION=1.0`.
func (r *variableResolver) declareEnvs(values []string) {
	if len(values)%3 != 0 {
		// BuildKit's parser always returns triples (legacy `ENV A b` gives ["A", "b", ""]); this only guards the
		// indexing below.
		return
	}
	type declaration struct {
		name  string
		value scopeValue
		known bool
	}
	declarations := make([]declaration, 0, len(values)/3)
	for i := 0; i < len(values); i += 3 {
		name, nameKnown := r.tryExpandValue(values[i], r.current.buildEnv)
		if !nameKnown {
			continue
		}
		value, known := r.tryExpandValue(values[i+1], r.current.buildEnv)
		declarations = append(declarations, declaration{name: name.text, value: value, known: known})
	}
	r.substituteValues(values, r.current.argValues, r.dockerfileSyntax)
	for _, d := range declarations {
		r.current.setEnv(d.name, d.value, d.known)
	}
}

// substituteFlags substitutes the values of the ADD/COPY flags that BuildKit expands, keeping the `--name=` prefix.
func (r *variableResolver) substituteFlags(flags []string, scope scopeEnv) {
	for i, flag := range flags {
		for _, prefix := range expandedFlagPrefixes {
			if value, ok := strings.CutPrefix(flag, prefix); ok {
				flags[i] = prefix + substituteReferences(value, scope, r.dockerfileSyntax)
				break
			}
		}
	}
}

func (r *variableResolver) substituteValues(values []string, scope scopeEnv, syntax referenceSyntax) {
	for i, value := range values {
		values[i] = substituteReferences(value, scope, syntax)
	}
}

// expandValue computes a variable value as Docker does (references expanded, quotes and escapes removed). Unknown
// references stay as written. If the value cannot be expanded, it is returned as written.
func (r *variableResolver) expandValue(value string, scope scopeEnv) string {
	expanded, known := r.tryExpandValue(value, scope)
	if !known {
		return value
	}
	return expanded.text
}

// tryExpandValue computes a declared value. The value is unresolved when it depends on an unknown name, directly
// (`ARG MIRROR=$UPSTREAM` where UPSTREAM has no value) or through another unresolved value. known is false when the
// lexer rejects the value.
func (r *variableResolver) tryExpandValue(value string, scope scopeEnv) (expanded scopeValue, known bool) {
	lex := shell.NewLex(r.escapeToken)
	lex.SkipUnsetEnv = true
	result, err := lex.ProcessWordWithMatches(value, scope)
	if err != nil {
		return scopeValue{}, false
	}
	return scopeValue{text: result.Result, unresolved: scope.dependsOnUnknown(result)}, true
}

// maxBracedReferenceLength bounds the search for the closing brace of a ${NAME<modifier>...} reference. Dockerfiles
// come from the scanned repository: without a bound, each unclosed `${NAME:-` would scan to the end of the text and
// the substitution would be quadratic. A longer reference is handled like an unclosed one.
const maxBracedReferenceLength = 512

// referenceSyntax describes how a text is read when its references are substituted.
type referenceSyntax struct {
	escapeToken byte
	// quoted makes single-quoted spans and escaped characters literal, as BuildKit's lexer does for the instructions
	// Docker expands. Shell text is not quoted (see shellSyntax).
	quoted bool
	// nameLength returns the length in bytes of the variable name at the start of a text, 0 if there is none.
	nameLength func(string) int
	// substituteUnresolvedOperands keeps a ${NAME<modifier>...} that cannot be computed as written, but still
	// substitutes the references inside its operand. Otherwise the whole reference is kept as written.
	substituteUnresolvedOperands bool
	// doubleDollarIsEscapedDollar reads `$$NAME` as `$` followed by $NAME, which is what a Makefile written from a
	// RUN script (`$$URL` in a recipe) or another interpreter expands. Otherwise `$$` is copied whole.
	doubleDollarIsEscapedDollar bool
}

// substituteReferences replaces the $NAME and ${NAME...} references whose NAME is in scope and copies everything else
// as written: quotes, escapes and unknown references. Inserted values are not scanned again.
func substituteReferences(text string, scope scopeEnv, syntax referenceSyntax) string {
	if len(scope) == 0 || !strings.Contains(text, "$") {
		return text
	}
	// The escape token is `\` or a backtick, and quotes, `$` and braces are ASCII: none of these bytes can appear
	// inside a multi-byte UTF-8 sequence, so the text can be scanned byte by byte.
	var out strings.Builder
	out.Grow(len(text))
	inDoubleQuotes := false
	for i := 0; i < len(text); {
		c := text[i]
		switch {
		case syntax.quoted && c == syntax.escapeToken:
			end := min(i+2, len(text))
			out.WriteString(text[i:end])
			i = end
		case syntax.quoted && c == '\'' && !inDoubleQuotes:
			end := len(text)
			if closing := strings.IndexByte(text[i+1:], '\''); closing >= 0 {
				end = i + 1 + closing + 1
			}
			out.WriteString(text[i:end])
			i = end
		case syntax.quoted && c == '"':
			inDoubleQuotes = !inDoubleQuotes
			out.WriteByte(c)
			i++
		case c == '$':
			replacement, length := substituteReference(text[i:], scope, syntax)
			out.WriteString(replacement)
			i += length
		default:
			out.WriteByte(c)
			i++
		}
	}
	return out.String()
}

// substituteReference handles the reference at the start of text (text[0] is `$`). It returns the replacement and the
// number of bytes it replaces.
func substituteReference(text string, scope scopeEnv, syntax referenceSyntax) (replacement string, length int) {
	if len(text) < 2 {
		return text, len(text)
	}
	if text[1] == '{' {
		return substituteBracedReference(text, scope, syntax)
	}
	nameEnd := 1 + syntax.nameLength(text[1:])
	if nameEnd == 1 {
		if text[1] == '$' && syntax.doubleDollarIsEscapedDollar {
			return "$", 1
		}
		if isSpecialParameter(text[1]) {
			// $1, $@... are shell parameters, and so is $$ outside shell text: they are copied whole.
			return text[:2], 2
		}
		return "$", 1
	}
	if value, ok := scope[text[1:nameEnd]]; ok {
		return value.text, nameEnd
	}
	return text[:nameEnd], nameEnd
}

// substituteBracedReference handles ${NAME} and ${NAME<modifier>word} (for example ${NAME:-default}). A reference to
// an unknown NAME, or one that BuildKit's lexer rejects, is kept as written (see substituteUnresolvedOperands).
func substituteBracedReference(text string, scope scopeEnv, syntax referenceSyntax) (replacement string, length int) {
	nameEnd := 2 + syntax.nameLength(text[2:])
	if nameEnd == 2 || nameEnd == len(text) {
		return "$", 1
	}
	name := text[2:nameEnd]
	if text[nameEnd] == '}' {
		if value, ok := scope[name]; ok {
			return value.text, nameEnd + 1
		}
		return text[:nameEnd+1], nameEnd + 1
	}
	if !strings.ContainsRune(":-+?#%/", rune(text[nameEnd])) {
		return "$", 1
	}
	end := endOfBracedReference(text[:min(len(text), maxBracedReferenceLength)], 0, syntax.escapeToken)
	if end < 0 {
		return "$", 1
	}
	reference := text[:end+1]
	unresolved := func() (string, int) {
		if syntax.substituteUnresolvedOperands {
			// Keep "${NAME" and let the caller scan the operand and the closing brace.
			return text[:nameEnd], nameEnd
		}
		return reference, len(reference)
	}
	if _, ok := scope[name]; !ok {
		return unresolved()
	}
	// The value is computed as BuildKit does: quotes and escapes in the operand or pattern are removed
	// (`${DEST#"stage"}` trims `stage`). Only the text around the reference keeps its quotes. A value that depends on
	// an unknown name, or on a value derived from one, cannot be computed: the placeholder `$UPSTREAM` stored for
	// `ARG MIRROR=$UPSTREAM` must not make ${MIRROR:-fallback} look set.
	result, err := shell.NewLex(rune(syntax.escapeToken)).ProcessWordWithMatches(reference, scope)
	if err != nil || scope.dependsOnUnknown(result) {
		return unresolved()
	}
	return result.Result, len(reference)
}

// endOfBracedReference returns the index of the `}` that closes the `${` at text[start], or -1. Like BuildKit's
// lexer, it skips escaped characters, quoted spans and nested ${...}, so `${A:+"r}oot"}` ends at the last brace.
func endOfBracedReference(text string, start int, escape byte) int {
	for i := start + 2; i < len(text); i++ {
		switch text[i] {
		case escape:
			i++
		case '\'':
			closing := strings.IndexByte(text[i+1:], '\'')
			if closing < 0 {
				return -1
			}
			i += 1 + closing
		case '"':
			if i = endOfDoubleQuotes(text, i, escape); i < 0 {
				return -1
			}
		case '$':
			if i+1 < len(text) && text[i+1] == '{' {
				if i = endOfBracedReference(text, i, escape); i < 0 {
					return -1
				}
			}
		case '}':
			return i
		}
	}
	return -1
}

// endOfDoubleQuotes returns the index of the `"` that closes the one at text[start], or -1.
func endOfDoubleQuotes(text string, start int, escape byte) int {
	for i := start + 1; i < len(text); i++ {
		switch text[i] {
		case escape:
			i++
		case '$':
			if i+1 < len(text) && text[i+1] == '{' {
				if i = endOfBracedReference(text, i, escape); i < 0 {
					return -1
				}
			}
		case '"':
			return i
		}
	}
	return -1
}

// dockerfileNameLength reads a name as BuildKit's lexer does (shell/lex.go processName): Unicode letters, digits and
// `_`, or only digits when it starts with a digit (`ARG 1=root` makes ${1} known).
func dockerfileNameLength(text string) int {
	n := 0
	digitsOnly := false
	for n < len(text) {
		r, size := utf8.DecodeRuneInString(text[n:])
		switch {
		case unicode.IsDigit(r):
			digitsOnly = digitsOnly || n == 0
		case digitsOnly || (r != '_' && !unicode.IsLetter(r)):
			return n
		}
		n += size
	}
	return n
}

// shellNameLength reads a POSIX shell name: ASCII letters, digits and `_`, not starting with a digit.
func shellNameLength(text string) int {
	n := 0
	for n < len(text) && (isNameStart(text[n]) || (n > 0 && text[n] >= '0' && text[n] <= '9')) {
		n++
	}
	return n
}

func isNameStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isSpecialParameter(c byte) bool {
	return (c >= '0' && c <= '9') || strings.IndexByte("$!?#@*-", c) >= 0
}

// scopeValue is the value of a declared variable.
type scopeValue struct {
	text string
	// unresolved marks a value that depends on an unknown name. text then keeps that name's reference as written
	// (`$UPSTREAM`): it is inserted for $NAME and ${NAME}, but a modifier on NAME cannot be computed from it.
	unresolved bool
}

// scopeEnv is a set of declared variables. It implements shell.EnvGetter for BuildKit's lexer.
type scopeEnv map[string]scopeValue

func (e scopeEnv) Get(name string) (string, bool) {
	value, ok := e[name]
	return value.text, ok
}

// dependsOnUnknown reports whether a lexer result used an unknown name or an unresolved value.
func (e scopeEnv) dependsOnUnknown(result shell.ProcessWordResult) bool {
	if len(result.Unmatched) > 0 {
		return true
	}
	for name := range result.Matched {
		if e[name].unresolved {
			return true
		}
	}
	return false
}

// set stores value, or makes name unknown when known is false.
func (e scopeEnv) set(name string, value scopeValue, known bool) {
	if !known {
		delete(e, name)
		return
	}
	e[name] = value
}

func (e scopeEnv) Keys() []string {
	return slices.Sorted(maps.Keys(e))
}
