# METADATA
# description: Contract v2 results rules must emit findings bound via result := dd_output.format(...)
package custom.regal.rules.contract["bound-finding"]

import data.custom.regal.lib.contract as lib
import data.regal.ast
import data.regal.result

_output_format := ["data", "datadog", "output", "format"]

# Reject any `results` partial-set rule whose head key is not a variable bound
# by `:= dd_output.format(...)` in its body (whitelist approach: catches inline
# objects, unification `=`, intermediate variables, and helper-built objects).
report contains violation if {
	lib.v2_query

	some rule in _result_rules
	rule.head.key
	not _bound_to_dd_output_format(rule)

	violation := result.fail(
		rego.metadata.chain(),
		object.union(
			result.location(rule.head.key),
			{"description": "Contract v2 `results` rules must bind `result := dd_output.format(resource, details)` and write `results contains result if { ... }`"},
		),
	)
}

_bound_to_dd_output_format(rule) if {
	rule.head.key.type == "var"
	var_name := rule.head.key.value
	some expr in rule.body
	ast.is_assignment(expr.terms[0])
	expr.terms[1].type == "var"
	expr.terms[1].value == var_name
	expr.terms[2].type == "call"
	lib.callee(expr.terms[2].value) == _output_format
}

_result_rules contains rule if {
	some rule in ast.rules
	ast.ref_to_string(rule.head.ref) == "results"
}
