package engine

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/require"
)

func TestDockerContractErrorsBeforeDecoding(t *testing.T) {
	for _, shared := range []bool{false, true} {
		name := "isolated"
		if shared {
			name = "prepared"
		}
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				name   string
				change func(*model.QueryMetadata, *Inspector, *dockerRuleInput)
				want   string
			}{
				{"missing rule version", func(q *model.QueryMetadata, _ *Inspector, _ *dockerRuleInput) {
					q.Content = strings.Replace(q.Content, "#       version: 1\n", "", 1)
				}, "missing custom.datadog.dockerfile.version"},
				{"unsupported rule version", func(q *model.QueryMetadata, _ *Inspector, _ *dockerRuleInput) {
					q.Content = strings.Replace(q.Content, "version: 1", "version: 2", 1)
				}, "requires contract version 2"},
				{"field slicing rejected", func(q *model.QueryMetadata, _ *Inspector, _ *dockerRuleInput) {
					q.Content = strings.Replace(q.Content, "#       kinds: [user]", "#       kinds: [user]\n#       facts: [/kind]", 1)
				}, `unknown Dockerfile contract metadata field "facts"`},
				{"missing library version", func(_ *model.QueryMetadata, ins *Inspector, _ *dockerRuleInput) {
					ins.QueryLoader.platformLibraries["Dockerfile"] = source.RegoLibraries{LibraryCode: "package generic.dockerfile", LibraryInputData: "{}"}
				}, "library is missing its contract version"},
				{"unsupported library version", func(_ *model.QueryMetadata, ins *Inspector, _ *dockerRuleInput) {
					ins.QueryLoader.platformLibraries["Dockerfile"] = source.RegoLibraries{LibraryCode: withDockerContractVersion("2", "package generic.dockerfile"), LibraryInputData: "{}"}
				}, "requires contract version 2"},
				{"invalid document identity", func(_ *model.QueryMetadata, _ *Inspector, d *dockerRuleInput) {
					doc := d.payload.(ast.Object).Get(ast.StringTerm("document")).Value.(*ast.Array).Elem(0).Value.(ast.Object)
					doc.Insert(ast.StringTerm("id"), ast.StringTerm(""))
				}, "invalid identity"},
				{"missing model version", func(_ *model.QueryMetadata, _ *Inspector, d *dockerRuleInput) {
					doc := d.payload.(ast.Object).Get(ast.StringTerm("document")).Value.(*ast.Array).Elem(0).Value.(ast.Object)
					facts := doc.Get(ast.StringTerm("_dockerfile")).Value.(ast.Object)
					withoutVersion := ast.NewObject()
					require.NoError(t, facts.Iter(func(key, value *ast.Term) error {
						if key.Value.Compare(ast.String("contract_version")) != 0 {
							withoutVersion.Insert(key, value)
						}
						return nil
					}))
					doc.Insert(ast.StringTerm("_dockerfile"), ast.NewTerm(withoutVersion))
				}, "missing contract_version"},
				{"legacy results rejected", func(q *model.QueryMetadata, _ *Inspector, _ *dockerRuleInput) {
					q.Content = withDockerContractVersion("1", `package datadog
DatadogPolicy contains {"documentId":"fixture", "searchKey":"USER"} if { true }`)
				}, "require a native node identity"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					q := dockerInstructionUnitMetadata("contract-regression")
					builds := 0
					builder := func(context.Context, *QueryContext, Tracker, interface{}, *detector.DetectLine, bool, time.Duration) (*model.Vulnerability, error) {
						builds++
						return &model.Vulnerability{}, nil
					}
					ins := newDockerInstructionUnitInspector(t, q, builder)
					d, raw, file := dockerInstructionUnitInput(t, "FROM alpine\nUSER app\n")
					tc.change(&q, ins, d)
					var plans map[int]*rego.PreparedEvalQuery
					if shared {
						// A prepared plan cannot bypass metadata/model validation. Compile
						// the changed rule separately, before the engine sees its metadata.
						prepared, err := rego.New(rego.Query("result = data.datadog.DatadogPolicy"),
							rego.Module("query.rego", q.Content), rego.Module("common.rego", dockerInstructionUnitCommon)).PrepareForEval(context.Background())
						require.NoError(t, err)
						plans = map[int]*rego.PreparedEvalQuery{0: &prepared}
					}
					result := ins.evalQuery(context.Background(), "scan", map[string]*model.FileMetadata{file.ID: file}, platformPayloads{dockerInput: d, byPlatform: map[string]ast.Value{"dockerfile": raw}, full: raw}, []model.QueryMetadata{q}, 0, nil, nil, nil, plans, nil)
					require.ErrorContains(t, result.err, tc.want)
					require.Empty(t, result.vulnerabilities)
					require.Zero(t, builds)
				})
			}
		})
	}
}

func TestDockerInstructionContractPreservesSecurityArguments(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		findings     int
	}{
		{"safe literal", "tool --safe", 0},
		{"unsafe literal", "tool", 1},
		{"unknown option", "tool $OPTION", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := dockerInstructionUnitMetadata("instruction-security-arguments")
			q.Content = `# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
#       scope: instruction
#       kinds: [run]
package datadog
import data.generic.common
has_safe_arg(call) if { some arg in call.arguments; arg.value == "--safe" }
DatadogPolicy contains common.finding(call) if {
  some document in input.document
  some instruction in document._dockerfile.instructions
  some call in instruction.execution.calls
  call.name == "tool"
  not has_safe_arg(call)
}`
			ins := newDockerInstructionUnitInspector(t, q, DefaultVulnerabilityBuilder)
			d, raw, file := dockerInstructionUnitInput(t, "FROM alpine\nSHELL [\"/bin/sh\",\"-c\"]\nARG OPTION\nRUN "+tc.script+"\n")
			result := ins.evalQuery(context.Background(), "scan", map[string]*model.FileMetadata{file.ID: file}, platformPayloads{dockerInput: d, byPlatform: map[string]ast.Value{"dockerfile": raw}, full: raw}, []model.QueryMetadata{q}, 0, nil, nil, nil, nil, nil)
			require.NoError(t, result.err)
			require.Len(t, result.vulnerabilities, tc.findings)
		})
	}
}

func TestDockerContractGateErrorRetractsEarlierRootFindings(t *testing.T) {
	query := dockerInstructionUnitMetadata("late-gate-error")
	builds := 0
	builder := func(_ context.Context, qCtx *QueryContext, _ Tracker, _ interface{}, _ *detector.DetectLine, _ bool, _ time.Duration) (*model.Vulnerability, error) {
		builds++
		// The first root was checked successfully. Simulate a gate failure
		// when the next root needs certainty validation.
		qCtx.dockerGate.initialized = true
		qCtx.dockerGate.err = fmt.Errorf("injected later gate failure")
		return &model.Vulnerability{FileID: "first"}, nil
	}
	ins := newDockerInstructionUnitInspector(t, query, builder)
	first := dockerRootTestDocument(t, "first", "FROM alpine\nUSER app\n")
	second := dockerRootTestDocument(t, "second", "FROM alpine\nARG U\nUSER $U\n")
	raw, err := ast.InterfaceToValue(map[string]interface{}{"document": []interface{}{first, second}})
	require.NoError(t, err)
	d, err := newDockerRuleInput(raw)
	require.NoError(t, err)
	result := ins.evalQuery(context.Background(), "scan", nil,
		platformPayloads{dockerInput: d, byPlatform: map[string]ast.Value{"dockerfile": raw}, full: raw},
		[]model.QueryMetadata{query}, 0, nil, nil, nil, nil, nil)
	require.Equal(t, 1, builds, "the first root produced a finding before the later gate failed")
	require.ErrorContains(t, result.err, "injected later gate failure")
	require.Empty(t, result.vulnerabilities, "a failed rule must retract all of its earlier findings")
}
