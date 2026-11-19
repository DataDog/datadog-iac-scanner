package engine

import (
	"sync"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/require"
)

func TestDockerUnknownIndexIsSharedAndReadOnly(t *testing.T) {
	const placeholder = "unique-unknown"
	known := ast.NewTerm(ast.NewArray(ast.StringTerm("known")))
	unknown := ast.NewTerm(ast.NewArray(ast.StringTerm("prefix-" + placeholder)))
	input := ast.NewObject(ast.Item(ast.StringTerm("known"), known), ast.Item(ast.StringTerm("unknown"), unknown))
	d := &dockerRuleInput{placeholder: placeholder, unknownValues: indexDockerUnknowns(input, placeholder)}
	require.False(t, d.unknownValues[known.Value])
	require.True(t, d.unknownValues[unknown.Value])
	size := len(d.unknownValues)
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Go(func() {
			for j := 0; j < 50; j++ {
				// New unit wrappers share indexed immutable children.
				unit := ast.NewObject(ast.Item(ast.StringTerm("facts"), unknown))
				if !d.hasUnknown(unit) {
					t.Error("shared unknown was lost")
				}
				unit = ast.NewObject(ast.Item(ast.StringTerm("facts"), known))
				if d.hasUnknown(unit) {
					t.Error("known shared facts became unknown")
				}
			}
		})
	}
	workers.Wait()
	require.Len(t, d.unknownValues, size, "query workers must never modify the shared scan index")
}
