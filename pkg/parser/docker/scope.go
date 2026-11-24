package docker

import (
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/command"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

// variableScope is the build environment of one stage. It follows BuildKit,
// where ARG and ENV write to a single environment: the last write wins, and a
// stage built FROM another stage starts from that stage's final environment.
// The inherited environment is shared through parent rather than copied, so a
// chain of stages costs only what each stage declares. A parent is never
// written after a stage derives from it. It satisfies the lexer's environment
// interface.
type variableScope struct {
	vars   map[string]string
	parent *variableScope
}

func newScope(vars map[string]string) *variableScope {
	if vars == nil {
		vars = map[string]string{}
	}
	return &variableScope{vars: vars}
}

func (s *variableScope) Get(name string) (string, bool) {
	for scope := s; scope != nil; scope = scope.parent {
		if value, ok := scope.vars[name]; ok {
			return value, true
		}
	}
	return "", false
}

func (s *variableScope) empty() bool {
	for scope := s; scope != nil; scope = scope.parent {
		if len(scope.vars) > 0 {
			return false
		}
	}
	return true
}

func (s *variableScope) Keys() []string {
	seen := map[string]struct{}{}
	var keys []string
	for scope := s; scope != nil; scope = scope.parent {
		for key := range scope.vars {
			if _, dup := seen[key]; !dup {
				seen[key] = struct{}{}
				keys = append(keys, key)
			}
		}
	}
	return keys
}

// stageScopes tracks the global ARGs declared before the first FROM and the
// final environment of every named stage.
type stageScopes struct {
	globals *variableScope
	named   map[string]*variableScope
}

func newStageScopes() *stageScopes {
	return &stageScopes{globals: newScope(nil), named: map[string]*variableScope{}}
}

// enter starts the scope of the stage opened by a FROM node. Global ARGs are
// visible to FROM itself but only enter the stage through an ARG declaration.
// A stage built on an earlier one inherits its environment, ARGs included.
// The base name is unquoted like any other FROM word, and stage names are
// case-insensitive.
func (st *stageScopes) enter(node *parser.Node, declaration *wordExpander) *variableScope {
	scope := newScope(nil)
	if node.Next == nil {
		return scope
	}
	base := expandValues(declaration, []string{node.Next.Value}, st.globals)[0]
	if parent, found := st.named[strings.ToLower(base)]; found {
		scope.parent = parent
	}
	if as := node.Next.Next; as != nil && strings.EqualFold(as.Value, "as") && as.Next != nil {
		st.named[strings.ToLower(as.Next.Value)] = scope
	}
	return scope
}

// expandCommand expands the values rules read and records declarations. FROM
// only sees global ARGs. ARG and ENV instructions keep their values as written,
// so rules can still see the references they contain; only the scope records
// the expanded values. ONBUILD triggers are not modeled: BuildKit runs a parent
// stage's triggers at the start of a derived stage, but they are neither
// expanded nor applied here.
func (s *variableScope) expandCommand(cmd *Command, globals *variableScope, lex, declaration *wordExpander) {
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
// replacing any value already set in the stage, as BuildKit does. The values
// themselves are returned as written.
func (s *variableScope) declareArgs(lex *wordExpander, values []string, globals *variableScope) []string {
	for _, value := range values {
		name, defaultValue, hasDefault := strings.Cut(value, "=")
		if hasDefault {
			s.vars[name] = expandValues(lex, []string{defaultValue}, s)[0]
		} else if global, ok := globals.Get(name); ok {
			s.vars[name] = global
		}
	}
	return values
}

// declareEnvs records the [name, value, separator] triples of one ENV
// instruction. Keys and values are expanded against the environment as it was
// before the instruction, and only then recorded. The values are returned as
// written, so a reference to a variable set by the same instruction stays
// visible to rules.
func (s *variableScope) declareEnvs(lex *wordExpander, values []string) []string {
	if len(values)%3 != 0 {
		return values
	}
	resolved := make([]string, len(values))
	for i := 0; i+1 < len(values); i += 3 {
		resolved[i] = expandValues(lex, []string{values[i]}, s)[0]
		resolved[i+1] = expandValues(lex, []string{values[i+1]}, s)[0]
	}
	for i := 0; i+1 < len(values); i += 3 {
		s.vars[resolved[i]] = resolved[i+1]
	}
	return values
}
