package unknowngate

import (
	"github.com/open-policy-agent/opa/v1/ast"
)

// docNode is a node of the taint memo of the virtual documents, keyed by ref terms.
type docNode struct {
	children *valueMap[*docNode]
	// element state, for a node that a derivation produced.
	derived  bool
	anyClean bool
	// dirty: a derivation that may produce this node or anything below it touched an unknown.
	dirty bool
	// below: some node in the subtree, this one included, is dirty or a tainted element.
	below bool
	// unknownKeys: keys of derived children that hold an unknown. A lookup of another key
	// may match one of them.
	unknownKeys []ast.Value
}

func newDocNode() *docNode { return &docNode{children: newValueMap[*docNode]()} }

func (n *docNode) child(k ast.Value, create bool) *docNode {
	if c, ok := n.children.get(k); ok {
		return c
	}
	if !create {
		return nil
	}
	c := newDocNode()
	n.children.put(k, c)
	return c
}

func (n *docNode) path(ref ast.Ref, create bool) []*docNode {
	nodes := make([]*docNode, 0, len(ref)+1)
	nodes = append(nodes, n)
	cur := n
	for _, t := range ref {
		cur = cur.child(t.Value, create)
		if cur == nil {
			break
		}
		nodes = append(nodes, cur)
	}
	return nodes
}

func (n *docNode) tainted() bool { return n.derived && !n.anyClean }

// derive records one derivation of the element at ref. unknownKey says that the last key
// of ref holds an unknown.
func (n *docNode) derive(ref ast.Ref, clean, unknownKey bool) {
	nodes := n.path(ref, true)
	leaf := nodes[len(nodes)-1]
	if unknownKey && !leaf.derived && len(nodes) > 1 {
		parent := nodes[len(nodes)-2]
		parent.unknownKeys = append(parent.unknownKeys, ref[len(ref)-1].Value)
	}
	leaf.derived = true
	leaf.anyClean = leaf.anyClean || clean
	if leaf.tainted() {
		// below stays set if a clean derivation follows: an over-approximation.
		markBelow(nodes)
	}
}

// markDirty records that a derivation of ref, or of anything below it when ref is only a
// prefix of the element, touched an unknown.
func (n *docNode) markDirty(ref ast.Ref) {
	nodes := n.path(ref, true)
	nodes[len(nodes)-1].dirty = true
	markBelow(nodes)
}

func markBelow(nodes []*docNode) {
	for _, x := range nodes {
		x.below = true
	}
}

// related reports whether a dirty node or a tainted element lies on the path to ref or below
// it: reading ref may then depend on an unknown.
func (n *docNode) related(ref ast.Ref) bool {
	nodes := n.path(ref, false)
	for _, x := range nodes {
		if x.dirty || x.tainted() {
			return true
		}
	}
	if len(nodes) == len(ref)+1 {
		return nodes[len(nodes)-1].below
	}
	return false
}

// missing returns the deepest node on the path to ref and the key of ref it has no child
// for, or nil when every node exists.
func (n *docNode) missing(ref ast.Ref) (*docNode, ast.Value) {
	nodes := n.path(ref, false)
	if len(nodes) == len(ref)+1 {
		return nil, nil
	}
	return nodes[len(nodes)-1], ref[len(nodes)-1].Value
}

// element returns the deepest derived element on the path to ref.
func (n *docNode) element(ref ast.Ref) *docNode {
	nodes := n.path(ref, false)
	for i := len(nodes) - 1; i > 0; i-- {
		if nodes[i].derived {
			return nodes[i]
		}
	}
	return nil
}

// callState is the taint of one function call, keyed by function and arguments.
type callState struct {
	// touched: a rule body of the call touched an unknown.
	touched bool
	// msg: a rule body touched an unknown only to render a string that flows to the value.
	msg bool
	// cleanPrimary: a rule that is neither an else branch nor a default produced the value
	// without touching an unknown.
	cleanPrimary bool
}

func (c *callState) tainted(messageSite bool) bool {
	return (c.touched && !c.cleanPrimary) || (c.msg && !messageSite)
}

// scopeMemo holds the memo of one virtual cache scope: OPA starts a fresh cache for every
// expression with a `with` modifier, so the memo does the same.
type scopeMemo struct {
	docs  *docNode
	calls *valueMap[*callState]
}

func newScopeMemo() *scopeMemo {
	return &scopeMemo{docs: newDocNode(), calls: newValueMap[*callState]()}
}
