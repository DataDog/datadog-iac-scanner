package unknowngate

import (
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// Fields of a result that identify it: two results with equal identity fields are the same
// finding. Every other field is presentation.
const (
	fieldBlock = "_dd_id"
	fieldPath  = "path"
	fieldKey   = "key"
)

var identityFields = [...]string{fieldBlock, fieldPath, fieldKey}

func isIdentityField(k string) bool {
	for _, f := range identityFields {
		if k == f {
			return true
		}
	}
	return false
}

// placeholder tests values against the unknown placeholder. Composite results are cached by
// identity, so repeated checks of the same block are O(1).
type placeholder struct {
	value ast.String
	cache map[ast.Value]bool
}

func newPlaceholder(s string) *placeholder {
	return &placeholder{value: ast.String(s), cache: map[ast.Value]bool{}}
}

func (p *placeholder) is(v ast.Value) bool {
	s, ok := v.(ast.String)
	return ok && s == p.value
}

func (p *placeholder) has(v ast.Value) bool {
	switch x := v.(type) {
	case ast.String:
		return x == p.value
	case *ast.Array:
		if r, ok := p.cache[x]; ok {
			return r
		}
		found := false
		for i := 0; i < x.Len() && !found; i++ {
			found = p.has(x.Elem(i).Value)
		}
		p.cache[x] = found
		return found
	case ast.Object:
		if r, ok := p.cache[x]; ok {
			return r
		}
		found := false
		_ = x.Iter(func(k, v *ast.Term) error {
			if p.has(k.Value) || p.has(v.Value) {
				found = true
				return errStop
			}
			return nil
		})
		p.cache[x] = found
		return found
	case ast.Set:
		if r, ok := p.cache[x]; ok {
			return r
		}
		found := false
		_ = x.Iter(func(e *ast.Term) error {
			if p.has(e.Value) {
				found = true
				return errStop
			}
			return nil
		})
		p.cache[x] = found
		return found
	}
	return false
}

// hasText reports whether v holds a string that embeds the placeholder text
// inside a larger string (jsonencode / templates / sprintf messages). The
// sentinel alone is not "text": callers that mean the whole value use is/has.
func (p *placeholder) hasText(v ast.Value) bool {
	if len(p.value) == 0 {
		return false
	}
	found := false
	ast.WalkTerms(ast.NewTerm(v), func(t *ast.Term) bool {
		s, ok := t.Value.(ast.String)
		if !ok {
			return false
		}
		str := string(s)
		if len(str) > len(p.value) && strings.Contains(str, string(p.value)) {
			found = true
		}
		return found
	})
	return found
}

type stopErr struct{}

func (stopErr) Error() string { return "stop" }

var errStop error = stopErr{}

// Identity returns the value that identifies a result of a rule. A result with `_dd_id` is
// identified by its `_dd_id`, `path` and `key` fields. Any other object result is identified
// by its fields minus those whose value holds the placeholder text (messages rendered from
// unknown values); any other result by itself.
func Identity(result ast.Value, placeholder string) ast.Value {
	id, _ := newPlaceholder(placeholder).identity(result)
	return id
}

// identity returns the identity of result and the fields it masked.
func (p *placeholder) identity(result ast.Value) (id ast.Value, masked []string) {
	obj, ok := result.(ast.Object)
	if !ok {
		return result, nil
	}
	if obj.Get(ast.InternedTerm(fieldBlock)) != nil {
		out := ast.NewObject()
		for _, f := range identityFields {
			k := ast.InternedTerm(f)
			if v := obj.Get(k); v != nil {
				out.Insert(k, v)
			}
		}
		return out, nil
	}
	_ = obj.Iter(func(k, v *ast.Term) error {
		if s, ok := k.Value.(ast.String); ok && p.hasText(v.Value) {
			masked = append(masked, string(s))
		}
		return nil
	})
	return maskFields(obj, masked), masked
}

// identityMasked returns the identity of result with the given fields masked, so a result
// re-evaluated with other values compares to the original one.
func (p *placeholder) identityMasked(result ast.Value, masked []string) ast.Value {
	obj, ok := result.(ast.Object)
	if !ok {
		return result
	}
	if obj.Get(ast.InternedTerm(fieldBlock)) != nil {
		id, _ := p.identity(result)
		return id
	}
	return maskFields(obj, masked)
}

func maskFields(obj ast.Object, masked []string) ast.Value {
	if len(masked) == 0 {
		return obj
	}
	out := ast.NewObject()
	_ = obj.Iter(func(k, v *ast.Term) error {
		if s, ok := k.Value.(ast.String); ok {
			for _, m := range masked {
				if string(s) == m {
					return nil
				}
			}
		}
		out.Insert(k, v)
		return nil
	})
	return out
}

// valueSet is a set of values keyed by hash and equality.
type valueSet struct {
	m map[int][]ast.Value
	n int
}

func newValueSet() *valueSet { return &valueSet{m: map[int][]ast.Value{}} }

func (s *valueSet) add(v ast.Value) bool {
	h := v.Hash()
	for _, x := range s.m[h] {
		if x.Compare(v) == 0 {
			return false
		}
	}
	s.m[h] = append(s.m[h], v)
	s.n++
	return true
}

func (s *valueSet) has(v ast.Value) bool {
	for _, x := range s.m[v.Hash()] {
		if x.Compare(v) == 0 {
			return true
		}
	}
	return false
}

// valueMap maps values, keyed by hash and equality, to T.
type valueMap[T any] struct {
	m map[int][]valueEntry[T]
}

type valueEntry[T any] struct {
	k ast.Value
	v T
}

func newValueMap[T any]() *valueMap[T] { return &valueMap[T]{m: map[int][]valueEntry[T]{}} }

func (m *valueMap[T]) get(k ast.Value) (T, bool) {
	for _, e := range m.m[k.Hash()] {
		if e.k.Compare(k) == 0 {
			return e.v, true
		}
	}
	var zero T
	return zero, false
}

func (m *valueMap[T]) put(k ast.Value, v T) {
	h := k.Hash()
	for i, e := range m.m[h] {
		if e.k.Compare(k) == 0 {
			m.m[h][i].v = v
			return
		}
	}
	m.m[h] = append(m.m[h], valueEntry[T]{k, v})
}
