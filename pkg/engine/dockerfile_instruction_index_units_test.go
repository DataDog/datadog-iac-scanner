package engine

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/require"
)

func TestDockerInstructionIndexSurvivesInstructionUnitNarrowing(t *testing.T) {
	const rule = `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
#       scope: instruction
#       kinds: [arg, env, from]
package datadog
DatadogPolicy contains {"_dd_id": instruction._dd_meta.id, "path": []} if {
	some document in input.document
	count(document._dockerfile.instructions) == 1
	some instruction in document._dockerfile.instructions
	instruction.index == 0
	instruction.kind != "arg"
	instruction.kind != "from"
}`
	query := model.QueryMetadata{Query: "first-instruction-unit-index", Platform: "Dockerfile", Content: rule}
	prepared, err := rego.New(
		rego.Query("result = data.datadog.DatadogPolicy"),
		rego.Module("rule", rule),
	).PrepareForEval(context.Background())
	require.NoError(t, err)

	for _, tc := range []struct {
		name, content string
		wantIDs       []string
	}{
		{
			name:    "reports initial bad instruction, not a later unit at array position zero",
			content: "ENV FIRST=bad\nFROM alpine\nENV LATER=bad\n",
			wantIDs: []string{"fixture#/_dockerfile/instructions/0"},
		},
		{
			name:    "accepts ARG as the first instruction",
			content: "ARG BASE=alpine\nENV LATER=bad\n",
		},
		{
			name:    "accepts FROM as the first instruction",
			content: "FROM alpine\nENV LATER=bad\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roots, _ := dockerUnitTestRoots(t, tc.content)
			units, err := dockerUnitRoots(&query, roots)
			require.NoError(t, err)
			var gotIDs []string
			for _, unit := range units {
				unitModel := unit.doc.Get(ast.StringTerm("_dockerfile")).Value.(ast.Object)
				instructions := unitModel.Get(ast.StringTerm("instructions")).Value.(*ast.Array)
				require.Equal(t, 1, instructions.Len(), "each policy evaluation receives one narrowed instruction")
				instruction := instructions.Elem(0).Value.(ast.Object)
				index := instruction.Get(ast.StringTerm("index")).Value.(ast.Number)
				payload := ast.NewObject()
				payload.Insert(ast.StringTerm("document"), ast.NewTerm(ast.NewArray(unit.term)))
				results, err := prepared.Eval(context.Background(), rego.EvalParsedInput(payload))
				require.NoError(t, err)
				items, err := resultItems(results)
				require.NoError(t, err)
				if len(items) != 0 {
					require.Equal(t, ast.Number("0"), index, "only the original first instruction can produce a finding")
					gotIDs = append(gotIDs, items[0].(map[string]interface{})["_dd_id"].(string))
				}
			}
			require.Equal(t, tc.wantIDs, gotIDs)
		})
	}
}
