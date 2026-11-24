package docker

import (
	"sort"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/command"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

// environment is what expansion reads variables from.
type environment interface {
	Get(name string) (string, bool)
	Keys() []string
	empty() bool
}

// binding is one ARG or ENV declaration. Its value is not expanded when it is
// declared: it keeps the raw word and the environment as it was just before the
// declaration, and expands on first read. A declaration that nothing reads
// therefore costs nothing, however much it would expand to.
type binding struct {
	seq      int
	expander *wordExpander
	raw      string
	env      view
	// A bare ARG takes the value of a global ARG of the same name.
	alias string

	value string
	done  bool
}

// resolve returns the value, expanding the declarations it depends on first.
// Dependencies are resolved from an explicit stack, so the depth of a chain of
// declarations costs heap, not goroutine stack.
func (b *binding) resolve() string {
	stack := []*binding{b}
	for len(stack) > 0 {
		top := stack[len(stack)-1]
		if top.done {
			stack = stack[:len(stack)-1]
			continue
		}
		if pending := top.tryResolve(); len(pending) > 0 {
			stack = append(stack, pending...)
		}
	}
	return b.value
}

// tryResolve expands the binding if every declaration it reads is already
// resolved. Otherwise it resolves nothing and returns the ones still needed.
func (b *binding) tryResolve() []*binding {
	reads := &tracker{view: b.env}
	if b.alias != "" {
		b.value, _ = reads.Get(b.alias)
	} else {
		b.value = expandValues(b.expander, []string{b.raw}, reads)[0]
	}
	if len(reads.pending) > 0 {
		return reads.pending
	}
	b.done = true
	b.env = view{} // The environment is no longer needed.
	return nil
}

// tracker is an environment that never resolves a declaration itself. A read of
// one that is not resolved yet is recorded and reported as present with an
// empty value, so a single pass discovers every dependency of the word. The
// caller discards that expansion and retries once they are resolved.
type tracker struct {
	view    view
	pending []*binding
	seen    map[*binding]struct{}
}

func (t *tracker) Get(name string) (string, bool) {
	b, ok := t.view.lookup(name)
	if !ok {
		return "", false
	}
	if !b.done {
		if _, dup := t.seen[b]; !dup {
			if t.seen == nil {
				t.seen = map[*binding]struct{}{}
			}
			t.seen[b] = struct{}{}
			t.pending = append(t.pending, b)
		}
		return "", true
	}
	return b.value, true
}

func (t *tracker) Keys() []string { return t.view.Keys() }
func (t *tracker) empty() bool    { return t.view.empty() }

// variableScope is the build environment of one stage. It follows BuildKit,
// where ARG and ENV write to a single environment: the last write wins, and a
// stage built FROM another stage starts from that stage's final environment.
// Declarations are recorded per name in the order they were made, so a binding
// can be read as of any earlier point, and a derived stage shares its parent's
// bindings through parent instead of copying them. A parent is never written
// after a stage derives from it.
type variableScope struct {
	vars   map[string][]*binding
	parent *variableScope
	next   int
}

func newScope() *variableScope {
	return &variableScope{vars: map[string][]*binding{}}
}

// view is the scope as it was at a point in time: only declarations made before
// limit are visible, and the parents are visible in full.
type view struct {
	scope *variableScope
	limit int
}

func (s *variableScope) now() view { return view{scope: s, limit: s.next} }

func (v view) lookup(name string) (*binding, bool) {
	limit := v.limit
	for scope := v.scope; scope != nil; scope = scope.parent {
		versions := scope.vars[name]
		// The last version declared before limit.
		i := sort.Search(len(versions), func(i int) bool { return versions[i].seq >= limit })
		if i > 0 {
			return versions[i-1], true
		}
		limit = int(^uint(0) >> 1)
	}
	return nil, false
}

func (v view) Get(name string) (string, bool) {
	b, ok := v.lookup(name)
	if !ok {
		return "", false
	}
	return b.resolve(), true
}

func (v view) Keys() []string {
	seen := map[string]struct{}{}
	var keys []string
	limit := v.limit
	for scope := v.scope; scope != nil; scope = scope.parent {
		for name, versions := range scope.vars {
			if _, dup := seen[name]; !dup && versions[0].seq < limit {
				seen[name] = struct{}{}
				keys = append(keys, name)
			}
		}
		limit = int(^uint(0) >> 1)
	}
	return keys
}

func (v view) empty() bool {
	for scope := v.scope; scope != nil; scope = scope.parent {
		if len(scope.vars) > 0 {
			return false
		}
	}
	return true
}

func (s *variableScope) Get(name string) (string, bool) { return s.now().Get(name) }
func (s *variableScope) Keys() []string                 { return s.now().Keys() }
func (s *variableScope) empty() bool                    { return s.now().empty() }

// declare records a binding. Bindings declared in one instruction share a
// sequence number, so none of them sees another's value.
func (s *variableScope) declare(name string, b *binding) {
	b.seq = s.next
	s.vars[name] = append(s.vars[name], b)
}

// stageScopes tracks the global ARGs declared before the first FROM and the
// final environment of every named stage.
type stageScopes struct {
	globals *variableScope
	named   map[string]*variableScope
}

func newStageScopes() *stageScopes {
	return &stageScopes{globals: newScope(), named: map[string]*variableScope{}}
}

// enter starts the scope of the stage opened by a FROM node. Global ARGs are
// visible to FROM itself but only enter the stage through an ARG declaration.
// A stage built on an earlier one inherits its environment, ARGs included.
// The base name is unquoted like any other FROM word, and stage names are
// case-insensitive.
func (st *stageScopes) enter(node *parser.Node, declaration *wordExpander) *variableScope {
	scope := newScope()
	if node.Next == nil {
		return scope
	}
	base := expandValues(declaration, []string{node.Next.Value}, st.globals.now())[0]
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
		cmd.Value = expandValues(lex, cmd.Value, globals.now())
	case command.Arg:
		cmd.Value = s.declareArgs(declaration, cmd.Value, globals)
	case command.Env:
		cmd.Value = s.declareEnvs(declaration, cmd.Value)
	case command.Onbuild:
	default:
		cmd.Value = expandValues(lex, cmd.Value, s.now())
	}
}

// declareArgs records ARG NAME=default. The default is expanded when something
// reads it, against the environment as it was before the declaration. A bare
// ARG NAME takes the global value when there is one, replacing any value already
// set in the stage, as BuildKit does. The values themselves are returned as
// written.
func (s *variableScope) declareArgs(lex *wordExpander, values []string, globals *variableScope) []string {
	for _, value := range values {
		name, defaultValue, hasDefault := strings.Cut(value, "=")
		if hasDefault {
			s.declare(name, &binding{expander: lex, raw: defaultValue, env: s.now()})
		} else if _, ok := globals.Get(name); ok {
			s.declare(name, &binding{alias: name, env: globals.now()})
		}
		s.next++
	}
	return values
}

// declareEnvs records the [name, value, separator] triples of one ENV
// instruction. Names are expanded now, since they decide what is declared;
// values when read. Both see the environment as it was before the instruction.
// The values are returned as written, so a reference to a variable set by the
// same instruction stays visible to rules.
func (s *variableScope) declareEnvs(lex *wordExpander, values []string) []string {
	if len(values)%3 != 0 {
		return values
	}
	before := s.now()
	for i := 0; i+1 < len(values); i += 3 {
		name := expandValues(lex, []string{values[i]}, before)[0]
		s.declare(name, &binding{expander: lex, raw: values[i+1], env: before})
	}
	s.next++
	return values
}
