package engine

import (
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// Index immutable composite values once per scan. Instruction units share
// stage inventories and source facts; rescanning each shared inventory for
// every unit would make unrelated instruction-local checks quadratic.
func indexDockerUnknowns(value ast.Value, placeholder string) map[ast.Value]bool {
	index := map[ast.Value]bool{}
	dockerUnknownValue(value, placeholder, index, true)
	return index
}

func dockerUnknownValue(value ast.Value, placeholder string, index map[ast.Value]bool, record bool) bool {
	if text, ok := value.(ast.String); ok {
		return strings.Contains(string(text), placeholder)
	}
	if found, cached := index[value]; cached {
		return found
	}
	found := false
	switch typed := value.(type) {
	case ast.Object:
		_ = typed.Iter(func(key, child *ast.Term) error {
			keyUnknown := dockerUnknownValue(key.Value, placeholder, index, record)
			valueUnknown := dockerUnknownValue(child.Value, placeholder, index, record)
			found = found || keyUnknown || valueUnknown
			return nil
		})
	case *ast.Array:
		for i := 0; i < typed.Len(); i++ {
			childUnknown := dockerUnknownValue(typed.Elem(i).Value, placeholder, index, record)
			found = found || childUnknown
		}
	case ast.Set:
		_ = typed.Iter(func(child *ast.Term) error {
			childUnknown := dockerUnknownValue(child.Value, placeholder, index, record)
			found = found || childUnknown
			return nil
		})
	default:
		return false
	}
	if record {
		index[value] = found
	}
	return found
}

func (d *dockerRuleInput) hasUnknown(value ast.Value) bool {
	return dockerUnknownValue(value, d.placeholder, d.unknownValues, false)
}
