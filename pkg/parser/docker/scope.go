package docker

import (
	"maps"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/command"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

// variableScope is the build environment of one stage. It follows BuildKit,
// where ARG and ENV write to a single environment: the last write wins, and a
// stage built FROM another stage starts from a copy of that stage's final
// environment. It satisfies the lexer's environment interface.
type variableScope map[string]string

func (s variableScope) Get(name string) (string, bool) {
	value, ok := s[name]
	return value, ok
}

func (s variableScope) Keys() []string {
	keys := make([]string, 0, len(s))
	for key := range s {
		keys = append(keys, key)
	}
	return keys
}

// stageScopes tracks the global ARGs declared before the first FROM and the
// final environment of every named stage.
type stageScopes struct {
	globals variableScope
	named   map[string]variableScope
}

func newStageScopes() *stageScopes {
	return &stageScopes{globals: variableScope{}, named: map[string]variableScope{}}
}

// enter starts the scope of the stage opened by a FROM node. Global ARGs are
// visible to FROM itself but only enter the stage through an ARG declaration.
// A stage built on an earlier one inherits its environment, ARGs included.
// The base name is unquoted like any other FROM word, and stage names are
// case-insensitive.
func (st *stageScopes) enter(node *parser.Node, declaration *wordExpander) variableScope {
	scope := variableScope{}
	if node.Next == nil {
		return scope
	}
	base := expandValues(declaration, []string{node.Next.Value}, st.globals)[0]
	if parent, found := st.named[strings.ToLower(base)]; found {
		scope = maps.Clone(parent)
	}
	if as := node.Next.Next; as != nil && strings.EqualFold(as.Value, "as") && as.Next != nil {
		st.named[strings.ToLower(as.Next.Value)] = scope
	}
	return scope
}

// expandCommand expands the values rules read and records declarations. FROM
// only sees global ARGs. ONBUILD triggers run in a later build, so they are
// neither expanded nor allowed to change this stage.
func (s variableScope) expandCommand(cmd *Command, globals variableScope, lex, declaration *wordExpander) {
	switch cmd.Cmd {
	case command.From:
		cmd.Value = expandValues(lex, cmd.Value, globals)
	case command.Arg:
		cmd.Value = s.declareArgs(declaration, cmd.Value, globals)
	case command.Env:
		cmd.Value = s.declareEnvs(declaration, cmd.Value)
	case command.Onbuild:
	default:
		cmd.Value = expandValues(lex, cmd.Value, s)
	}
}

// declareArgs records ARG NAME=default, expanding the default against the
// environment so far. A bare ARG NAME takes the global value when there is one,
// replacing any value already set in the stage, as BuildKit does.
func (s variableScope) declareArgs(lex *wordExpander, values []string, globals variableScope) []string {
	for i, value := range values {
		name, defaultValue, hasDefault := strings.Cut(value, "=")
		if hasDefault {
			resolved := expandValues(lex, []string{defaultValue}, s)[0]
			s[name] = resolved
			values[i] = name + "=" + resolved
		} else if global, ok := globals[name]; ok {
			s[name] = global
		}
	}
	return values
}

// declareEnvs records the [name, value, separator] triples of one ENV
// instruction. Keys and values are all expanded against the environment as it
// was before the instruction, and only then recorded.
func (s variableScope) declareEnvs(lex *wordExpander, values []string) []string {
	if len(values)%3 != 0 {
		return values
	}
	for i := 0; i < len(values); i += 3 {
		values[i] = expandValues(lex, []string{values[i]}, s)[0]
		values[i+1] = expandValues(lex, []string{values[i+1]}, s)[0]
	}
	for i := 0; i < len(values); i += 3 {
		s[values[i]] = values[i+1]
	}
	return values
}
