package docker

import (
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/command"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

// envNode is a persistent AVL tree node mapping variable names to bindings.
// Immutability gives O(1) stage inheritance (sharing the parent's root) and
// O(1) point-in-time snapshots for lazy declarations, with O(log K) lookup
// regardless of how deep a chain of FROM <stage> stages grows.
type envNode struct {
	key    string
	val    *binding
	left   *envNode
	right  *envNode
	height int
}

func (n *envNode) get(key string) (*binding, bool) {
	for cur := n; cur != nil; {
		switch {
		case key < cur.key:
			cur = cur.left
		case key > cur.key:
			cur = cur.right
		default:
			return cur.val, true
		}
	}
	return nil, false
}

func (n *envNode) has(key string) bool {
	_, ok := n.get(key)
	return ok
}

func (n *envNode) set(key string, val *binding) *envNode {
	if n == nil {
		return &envNode{key: key, val: val, height: 1}
	}
	switch {
	case key < n.key:
		return newEnvNode(n.key, n.val, n.left.set(key, val), n.right).balance()
	case key > n.key:
		return newEnvNode(n.key, n.val, n.left, n.right.set(key, val)).balance()
	default:
		return newEnvNode(key, val, n.left, n.right)
	}
}

func (n *envNode) keys(out []string) []string {
	if n == nil {
		return out
	}
	out = n.left.keys(out)
	out = append(out, n.key)
	return n.right.keys(out)
}

func nodeHeight(n *envNode) int {
	if n == nil {
		return 0
	}
	return n.height
}

func newEnvNode(key string, val *binding, left, right *envNode) *envNode {
	h := max(nodeHeight(left), nodeHeight(right)) + 1
	return &envNode{key: key, val: val, left: left, right: right, height: h}
}

func (n *envNode) balance() *envNode {
	diff := nodeHeight(n.left) - nodeHeight(n.right)
	if diff > 1 {
		left := n.left
		if nodeHeight(left.left) < nodeHeight(left.right) {
			left = left.rotateLeft()
		}
		return newEnvNode(n.key, n.val, left, n.right).rotateRight()
	}
	if diff < -1 {
		right := n.right
		if nodeHeight(right.right) < nodeHeight(right.left) {
			right = right.rotateRight()
		}
		return newEnvNode(n.key, n.val, n.left, right).rotateLeft()
	}
	return n
}

func (n *envNode) rotateRight() *envNode {
	l := n.left
	return newEnvNode(l.key, l.val, l.left, newEnvNode(n.key, n.val, l.right, n.right))
}

func (n *envNode) rotateLeft() *envNode {
	r := n.right
	return newEnvNode(r.key, r.val, newEnvNode(n.key, n.val, n.left, r.left), r.right)
}

// binding is one ARG or ENV declaration. Its value stays unexpanded until a
// later instruction actually reads it, capturing the immutable environment from
// just before the declaration.
type binding struct {
	expander *wordExpander
	raw      string
	env      *envNode

	value string
	done  bool
}

// resolveBindings resolves roots and all transitive dependencies in topological
// order using an explicit stack. Dependencies are discovered statically by
// scanning raw syntax without running substitutions, so unresolved bindings
// never produce placeholder values and each reachable binding expands once.
func resolveBindings(roots []*binding) {
	type frame struct {
		b      *binding
		scan   wordScan
		pushed bool
	}
	stack := make([]frame, 0, len(roots))
	for _, b := range roots {
		if !b.done {
			stack = append(stack, frame{b: b})
		}
	}
	for len(stack) > 0 {
		top := &stack[len(stack)-1]
		if top.b.done {
			stack = stack[:len(stack)-1]
			continue
		}
		if !top.pushed {
			top.pushed = true
			if top.b.expander.mayReference(top.b.raw) {
				top.scan = scanWord(top.b.raw, top.b.expander.escape)
				plainOnly := !canUseLexer(top.b.raw, top.scan, top.b.env)
				for _, dep := range unresolvedDeps(top.scan.refs, top.b.env, plainOnly) {
					stack = append(stack, frame{b: dep})
				}
			}
			continue
		}
		b, scan := top.b, top.scan
		stack = stack[:len(stack)-1]
		if b.expander.mayReference(b.raw) {
			b.value = b.expander.expandResolved(b.raw, scan, b.env)
		} else {
			b.value = b.raw
		}
		b.done = true
		b.env = nil // release immutable scope snapshot once materialized
	}
}

// unresolvedDeps returns the distinct unresolved bindings referenced by refs.
// When plainOnly is true, the word will take the plain-reference fallback, so
// non-plain references are ignored and their bindings stay lazy.
func unresolvedDeps(refs []wordRef, env *envNode, plainOnly bool) []*binding {
	if env == nil || len(refs) == 0 {
		return nil
	}
	var deps []*binding
	var seen map[*binding]struct{}
	for _, ref := range refs {
		if plainOnly && (!ref.plain || !isIdentifierName(ref.name)) {
			continue
		}
		dep, ok := env.get(ref.name)
		if !ok || dep.done {
			continue
		}
		if len(refs) > 1 {
			if _, dup := seen[dep]; dup {
				continue
			}
			if seen == nil {
				seen = make(map[*binding]struct{}, len(refs))
			}
			seen[dep] = struct{}{}
		}
		deps = append(deps, dep)
	}
	return deps
}

// stageScopes tracks global ARGs (before the first FROM), the current stage's
// environment, and the final environment of every named stage. It follows
// BuildKit, where ARG and ENV write to one environment per stage (last write
// wins) and a stage built FROM another stage starts from its parent's final
// environment.
type stageScopes struct {
	globals *envNode
	named   map[string]*envNode
	stage   *envNode
	name    string // lowercase alias of the current stage, "" if unnamed
	inStage bool
}

func newStageScopes() *stageScopes {
	return &stageScopes{named: map[string]*envNode{}}
}

func (st *stageScopes) current() *envNode {
	if st.inStage {
		return st.stage
	}
	return st.globals
}

func (st *stageScopes) set(name string, b *binding) {
	if !st.inStage {
		st.globals = st.globals.set(name, b)
		return
	}
	st.stage = st.stage.set(name, b)
	if st.name != "" {
		st.named[st.name] = st.stage
	}
}

// enter starts the scope of the stage opened by a FROM node. Global ARGs are
// visible to FROM itself but only enter the stage through an ARG declaration.
// A stage built on an earlier one inherits its environment, ARGs included.
// The base name is unquoted like any other FROM word, and stage names are
// case-insensitive.
func (st *stageScopes) enter(node *parser.Node, declaration *wordExpander) {
	st.inStage = true
	st.stage = nil
	st.name = ""
	if node.Next == nil {
		return
	}
	base := expandValues(declaration, []string{node.Next.Value}, st.globals)[0]
	if parent, found := st.named[strings.ToLower(base)]; found {
		st.stage = parent
	}
	if as := node.Next.Next; as != nil && strings.EqualFold(as.Value, "as") && as.Next != nil {
		st.name = strings.ToLower(as.Next.Value)
		st.named[st.name] = st.stage
	}
}

// expandCommand expands the values rules read and records declarations. FROM
// only sees global ARGs. ARG and ENV instructions keep their values as written,
// so rules can still see the references they contain; only the scope records
// the declarations. ONBUILD triggers are not modeled: BuildKit runs a parent
// stage's triggers at the start of a derived stage, but they are neither
// expanded nor applied here.
func (st *stageScopes) expandCommand(cmd *Command, lex, declaration *wordExpander) {
	switch cmd.Cmd {
	case command.From:
		cmd.Value = expandValues(lex, cmd.Value, st.globals)
	case command.Arg:
		st.declareArgs(declaration, cmd.Value)
	case command.Env:
		st.declareEnvs(declaration, cmd.Value)
	case command.Onbuild:
	default:
		cmd.Value = expandValues(lex, cmd.Value, st.current())
	}
}

// declareArgs records ARG NAME=default lazily against the environment so far.
// A bare ARG NAME takes the global binding when there is one (without forcing
// it yet), replacing any value already set in the stage, as BuildKit does.
func (st *stageScopes) declareArgs(lex *wordExpander, values []string) {
	for _, value := range values {
		name, defaultValue, hasDefault := strings.Cut(value, "=")
		if hasDefault {
			st.set(name, &binding{expander: lex, raw: defaultValue, env: st.current()})
		} else if global, ok := st.globals.get(name); ok {
			st.set(name, global)
		}
	}
}

// declareEnvs records the [name, value, separator] triples of one ENV
// instruction. Keys are expanded immediately because they determine what is
// declared; values stay lazy until read. Both see the environment from before
// the instruction.
func (st *stageScopes) declareEnvs(lex *wordExpander, values []string) {
	if len(values)%3 != 0 {
		return
	}
	before := st.current()
	for i := 0; i+1 < len(values); i += 3 {
		name := expandValues(lex, []string{values[i]}, before)[0]
		st.set(name, &binding{expander: lex, raw: values[i+1], env: before})
	}
}
