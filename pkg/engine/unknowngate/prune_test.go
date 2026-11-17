package unknowngate

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubstitutionValuesKeepsComparedConstants(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog

required := {"Team"}

type_map := {
	"aws_s3_bucket": "",
	"aws_instance": "",
}

taggable(t) if type_map[t]

DatadogPolicy contains {"rule": "tags", "name": name} if {
	some b in input.blocks
	taggable(b.type)
	some req in required
	not has_tag(b, req)
	name := b.name
}

has_tag(b, req) if {
	some k, _ in b.tags
	lower(k) == lower(req)
}

DatadogPolicy contains {"rule": "acl", "name": name} if {
	some b in input.blocks
	b.acl == "private"
	name := b.name
}
`)
	got := valueStrings(g.values)
	assert.Contains(t, got, `"Team"`, "compared with tag keys from input")
	assert.Contains(t, got, `"private"`, "compared with input attribute")
	assert.NotContains(t, got, `"aws_s3_bucket"`, "type-name map key, never compared with an unknown")
	assert.NotContains(t, got, `"aws_instance"`, "type-name map key, never compared with an unknown")
	assert.NotContains(t, got, `"rule"`, "result object key")
	assert.NotContains(t, got, `"name"`, "result object key")
}

func TestSubstitutionValuesKeepsDynamicObjectKeyCollisionConstants(t *testing.T) {
	for _, key := range []string{`"safe"`, `["safe"]`, `{"safe"}`, `{"safe": true}`} {
		t.Run(key, func(t *testing.T) {
			g := newTestGate(t, testPlaceholder, fmt.Sprintf(`package datadog
import rego.v1

derived := {input.block.id: true, %s: true}

DatadogPolicy contains {"_dd_id": "object_count", "path": [], "key": "", "block": {}} if {
	count(derived) == 2
}

DatadogPolicy contains {"_dd_id": "key_count", "path": [], "key": "", "block": {}} if {
	keys := [key | some key, _ in derived]
	count(keys) == 2
}
`, key))

			assert.Contains(t, valueStrings(g.values), ast.MustParseTerm(key).Value.String(), "a literal object key can collide with a computed key")
			input := mustValue(t, `{"block":{"id":"`+testPlaceholder+`"}}`)
			results, err := g.Results(context.Background(), input)
			require.NoError(t, err)
			require.Len(t, results, 2)
			scope := input.(ast.Object).Get(ast.StringTerm("block")).Value
			candidates := []Candidate{
				{Result: results[0], Scope: []ast.Value{scope}},
				{Result: results[1], Scope: []ast.Value{scope}},
			}
			report, err := g.Check(context.Background(), input, candidates)
			require.NoError(t, err)
			require.Len(t, report.Verdicts, len(candidates))
			for _, verdict := range report.Verdicts {
				assert.True(t, verdict.Uncertain)
				assert.Equal(t, StageSubstitution, verdict.Stage)
			}
		})
	}
}

func TestSubstitutionValuesKeepsPortsFromObjectKeys(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog

ports := {22: "SSH", 3389: "RDP"}

sensitive(rule) if {
	some port in object.keys(ports)
	rule.from_port <= port
	rule.to_port >= port
}

DatadogPolicy contains {"rule": "port", "name": name} if {
	some b in input.blocks
	some rule in b.ingress
	sensitive(rule)
	name := b.name
}
`)
	got := valueStrings(g.values)
	assert.Contains(t, got, "22", "port compared with from_port/to_port")
	assert.Contains(t, got, "3389", "port compared with from_port/to_port")
}

func TestSubstitutionValuesDropsUnusedLibraryConstants(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog

unused := {"aws_accessanalyzer_analyzer", "aws_acm_certificate"}

DatadogPolicy contains {"rule": "enc", "name": name, "issueType": "IncorrectValue"} if {
	some b in input.blocks
	b.enc == false
	name := b.name
}
`)
	got := valueStrings(g.values)
	assert.NotContains(t, got, `"aws_accessanalyzer_analyzer"`)
	assert.NotContains(t, got, `"aws_acm_certificate"`)
	assert.NotContains(t, got, `"issueType"`)
	assert.NotContains(t, got, `"IncorrectValue"`, "only used as a result field value, not compared with input")
	assert.Contains(t, got, "false", "base value always kept")
}

func TestSubstitutionValuesKeepsFalseThroughHelper(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog

is_equal(secure, target) if {
	secure == target
} else if {
	target in secure
}

DatadogPolicy contains {"rule": "http", "id": id} if {
	some b in input.blocks
	policy := read_policy(b)
	is_object(policy)
	some st in policy.Statement
	is_equal(st.Condition.Bool["aws:SecureTransport"], "false")
	id := b.id
}

read_policy(b) := b.policy
`)
	got := valueStrings(g.values)
	assert.Contains(t, got, `"false"`, "string compared through is_equal must stay substitutable")
}

// Production S3 path: tf.blocks + tf.json (input._dd indexes), not a direct
// input.blocks read. Without marking input-derived library calls as MU, the
// gate drops "false" and certifies an unresolved SecureTransport finding.
func TestSubstitutionValuesKeepsFalseThroughBlocksAndJSON(t *testing.T) {
	g := newMultiModuleGate(t, testPlaceholder, map[string]string{
		"terraform.rego": `package generic.terraform

_dd := object.get(input, "_dd", {})

_index(name) := object.get(_dd, name, {})

_typed_blocks(kind, type) := object.get(_index("blocks"), [kind, type], [])

blocks(type) := _typed_blocks("resource", type)

_meta(block) := block._dd_meta if is_object(block._dd_meta) else := {}

_path_key(path) := path if is_string(path)

_derived(block, kind, path) := object.get(_meta(block), ["derived", kind, _path_key(path)], null)

json(block, path) := doc if {
	doc := _derived(block, "json", path)
	doc != null
}
`,
		"common.rego": `package generic.common

policy_statements(policy) := st if {
	is_object(policy.Statement)
	st := [policy.Statement]
} else := st if {
	is_array(policy.Statement)
	st := policy.Statement
}
`,
		"rule.rego": `package datadog

import data.generic.terraform as tf
import data.generic.common as common

is_equal(secure, target) if {
	secure == target
} else if {
	target in secure
}

DatadogPolicy contains {"rule": "http", "id": id} if {
	some resource in tf.blocks("aws_s3_bucket_policy")
	policy := tf.json(resource, "policy")
	is_object(policy)
	not deny_http(policy)
	id := resource.id
}

deny_http(policy) if {
	some statement in common.policy_statements(policy)
	statement.Effect == "Deny"
	is_equal(statement.Condition.Bool["aws:SecureTransport"], "false")
}
`,
	})
	got := valueStrings(g.values)
	assert.Contains(t, got, `"false"`, "tf.blocks/tf.json path must keep SecureTransport substitution")
}

// Unresolved aws:SecureTransport on a Deny statement: substituting "false"
// makes deny_http succeed and removes the finding, so the gate must drop it.
func TestUnresolvedSecureTransportIsUncertainThroughBlocksAndJSON(t *testing.T) {
	g := newMultiModuleGate(t, testPlaceholder, map[string]string{
		"terraform.rego": `package generic.terraform

_dd := object.get(input, "_dd", {})

_index(name) := object.get(_dd, name, {})

_typed_blocks(kind, type) := object.get(_index("blocks"), [kind, type], [])

blocks(type) := _typed_blocks("resource", type)

_meta(block) := block._dd_meta if is_object(block._dd_meta) else := {}

_path_key(path) := path if is_string(path)

_derived(block, kind, path) := object.get(_meta(block), ["derived", kind, _path_key(path)], null)

json(block, path) := doc if {
	doc := _derived(block, "json", path)
	doc != null
}
`,
		"common.rego": `package generic.common

policy_statements(policy) := st if {
	is_array(policy.Statement)
	st := policy.Statement
}
`,
		"rule.rego": `package datadog

import data.generic.terraform as tf
import data.generic.common as common

is_equal(secure, target) if {
	secure == target
} else if {
	target in secure
}

DatadogPolicy contains {"rule": "http", "name": name} if {
	some resource in tf.blocks("aws_s3_bucket_policy")
	policy := tf.json(resource, "policy")
	is_object(policy)
	not deny_http(policy)
	name := resource.name
}

deny_http(policy) if {
	some statement in common.policy_statements(policy)
	statement.Effect == "Deny"
	is_equal(statement.Condition.Bool["aws:SecureTransport"], "false")
}
`,
	})
	input := mustValue(t, `{
		"_dd": {
			"blocks": {
				"resource": {
					"aws_s3_bucket_policy": [{
						"name": "b",
						"id": "b1",
						"_dd_meta": {
							"id": "b1",
							"derived": {
								"json": {
									"policy": {
										"Statement": [{
											"Effect": "Deny",
											"Action": "s3:*",
											"Condition": {"Bool": {"aws:SecureTransport": "${...}"}}
										}]
									}
								}
							}
						}
					}]
				}
			}
		}
	}`)
	got := verdicts(t, g, input)
	require.Contains(t, got, "http/b")
	assert.True(t, got["http/b"].Uncertain, "unresolved SecureTransport must not certify a finding: %v", got["http/b"])
}

func TestPrunedValuesDoNotChangeVerdicts(t *testing.T) {
	src := `package datadog

types := {"aws_s3_bucket": "", "aws_instance": ""}

ok_type(t) if types[t]

DatadogPolicy contains {"rule": "acl", "name": name} if {
	some b in input.blocks
	ok_type(b.type)
	not b.acl == "private"
	name := b.name
}
`
	g := newTestGate(t, testPlaceholder, src)
	input := mustValue(t, `{"blocks": [
		{"name": "k", "type": "aws_s3_bucket", "acl": "public-read"},
		{"name": "u", "type": "aws_s3_bucket", "acl": "${...}"}
	]}`)
	got := verdicts(t, g, input)
	assert.False(t, got["acl/k"].Uncertain)
	assert.True(t, got["acl/u"].Uncertain)
	require.NotContains(t, valueStrings(g.values), `"aws_s3_bucket"`)
}

func valueStrings(vals []ast.Value) []string {
	out := make([]string, len(vals))
	for i, v := range vals {
		out[i] = v.String()
	}
	return out
}

func TestInputKeyedObjectDoesNotProveStaticSelectorDomain(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog

domains[input.selector] := {"type": ""}

DatadogPolicy contains {"rule": "selector", "name": b.name} if {
	some typ, _ in domains
	some b in input.blocks[typ]
	typ != "safe"
}
`)
	assert.Contains(t, valueStrings(g.values), `"safe"`,
		"the selector is produced from input and its comparison value must remain substitutable")

	input := mustValue(t, `{"selector":"${...}","blocks":{
		"${...}":[{"name":"dynamic"}],
		"safe":[{"name":"safe"}]
	}}`)
	got := verdicts(t, g, input)
	assert.True(t, got["selector/dynamic"].Uncertain,
		"substituting the selector to safe removes this input-derived result")
}

func TestWithOverrideDisablesStaticDomainProofInCallee(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog

static_types := {"safe": ""}

select_types contains candidate if {
	some candidate, _ in static_types
}

DatadogPolicy contains {"rule": "selector", "name": b.name} if {
	some typ in select_types with data.datadog.static_types as input.selector_map
	some b in input.blocks[typ]
	typ != "safe"
}
`)
	assert.Contains(t, valueStrings(g.values), `"safe"`,
		"the caller's with replacement makes the callee's apparent ground map input-derived")

	input := mustValue(t, `{"selector_map":{"${...}":""},"blocks":{
		"${...}":[{"name":"dynamic"}],
		"safe":[{"name":"safe"}]
	}}`)
	got := verdicts(t, g, input)
	assert.True(t, got["selector/dynamic"].Uncertain,
		"substituting the with-provided selector to safe removes this result")
}

func TestStaticAliasDoesNotEraseInputTaint(t *testing.T) {
	g := newTestGate(t, "safe", `package datadog

allowed := {"safe": "", "other": ""}

DatadogPolicy contains {"rule": "alias", "name": b.name} if {
	some key, _ in allowed
	alias := input.selector
	alias == key
	some b in input.blocks[alias]
	alias != "other"
}
`)
	assert.Contains(t, valueStrings(g.values), `"other"`,
		"a ground-domain alias must not hide that alias also comes from input")

	input := mustValue(t, `{"selector":"safe","blocks":{
		"safe":[{"name":"u"}],
		"other":[{"name":"other"}]
	}}`)
	got := verdicts(t, g, input)
	assert.True(t, got["alias/u"].Uncertain,
		"substituting the input alias from safe to other removes the result")
}

func TestGroundObjectKeyDomainStaysStaticWhenSelectingInput(t *testing.T) {
	var src strings.Builder
	src.WriteString("package datadog\n\nresource_types := {\n")
	for i := 0; i < 120; i++ {
		fmt.Fprintf(&src, "\t%q: \"\",\n", fmt.Sprintf("test_resource_%03d", i))
	}
	src.WriteString(`}

DatadogPolicy contains {"rule": "value", "name": b.name} if {
	some typ, _ in resource_types
	some b in input.blocks[typ]
	b.tags.team != false
}

DatadogPolicy contains {"rule": "key", "name": b.name} if {
	some typ, _ in resource_types
	some b in input.blocks[typ]
	some key, _ in b.tags
	key != "team"
}
`)
	g := newTestGate(t, testPlaceholder, src.String())
	gotValues := valueStrings(g.values)
	assert.Contains(t, gotValues, `"team"`, "input-derived tag keys must keep their comparison constant")
	for i := 0; i < 120; i++ {
		assert.NotContains(t, gotValues, fmt.Sprintf(`"test_resource_%03d"`, i))
	}
	assert.Less(t, len(g.companions), 20, "static selector names must not produce substitution companions")

	input := mustValue(t, `{"blocks": {
		"test_resource_001": [{"name": "value", "tags": {"team": "${...}"}}],
		"test_resource_002": [{"name": "key", "tags": {"${...}": "x"}}]
	}}`)
	got := verdicts(t, g, input)
	assert.True(t, got["value/value"].Uncertain, "the unknown tag value may become false")
	assert.True(t, got["key/key"].Uncertain, "the unknown tag key may become team")
}

func TestMixedGroundAndInputDerivedDomainRemainsUnknown(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog

resource_types contains "known_type"
resource_types contains input.dynamic_type

DatadogPolicy contains {"rule": "value", "name": b.name} if {
	some typ in resource_types
	some b in input.blocks[typ]
	b.value != "safe"
}
`)
	assert.Contains(t, valueStrings(g.values), `"safe"`, "the input-derived domain can select an input block")
	input := mustValue(t, `{"dynamic_type": "dynamic_type", "blocks": {"dynamic_type": [{"name": "u", "value": "${...}"}]}}`)
	got := verdicts(t, g, input)
	assert.True(t, got["value/u"].Uncertain, "the input-derived selector and value remain substitutable")
}

func TestOutputHelperKeepsStaticComparisonConstant(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog

allowed := {"safe": ""}

same(actual, expected) := actual == expected

DatadogPolicy contains {"rule": "value", "name": b.name} if {
	some expected, _ in allowed
	some b in input.blocks
	not same(b.value, expected)
}
`)
	assert.Contains(t, valueStrings(g.values), `"safe"`, "the helper body compares an unknown with a static expected value")
	input := mustValue(t, `{"blocks":[{"name":"u","value":"${...}"}]}`)
	got := verdicts(t, g, input)
	assert.True(t, got["value/u"].Uncertain, "substituting the unknown value removes the helper result")
}

func TestContainsKeepsStaticExpectedValue(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog

allowed := {"safe": ""}

DatadogPolicy contains {"rule": "value", "name": b.name} if {
	some expected, _ in allowed
	some b in input.blocks
	not contains(b.value, expected)
}
`)
	assert.Contains(t, valueStrings(g.values), `"safe"`, "contains compares unknown input with a static expected value")
	input := mustValue(t, `{"blocks":[{"name":"u","value":"${...}"}]}`)
	got := verdicts(t, g, input)
	assert.True(t, got["value/u"].Uncertain, "substituting the unknown value can make contains false")
}
