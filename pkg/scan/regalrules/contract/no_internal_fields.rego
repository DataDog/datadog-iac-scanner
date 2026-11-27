# METADATA
# description: Contract v2 rules must not reference internal _dd engine fields
package custom.regal.rules.contract["no-internal-fields"]

import data.custom.regal.lib.contract as lib
import data.regal.result

# Flag `_dd` / `_dd_*` only when accessed as a ref field (not arbitrary tag or
# attribute string values like `iac.equals(r, ["tags", "_dd_managed"], "true")`).
report contains violation if {
	lib.v2_query

	walk(input.rules, [_, term])
	term.type == "ref"
	some i, step in term.value
	i > 0
	step.type == "string"
	_internal(step.value)

	violation := result.fail(
		rego.metadata.chain(),
		object.union(
			result.location(step),
			{"description": sprintf("%q is an internal engine field; use data.datadog.iac and dd_output.format instead", [step.value])},
		),
	)
}

report contains violation if {
	lib.v2_query

	some rule in input.rules
	some call in lib.calls_in(rule)
	lib.callee(call) == ["object", "get"]
	count(call) >= 3
	key_term := _internal_object_get_key(call[2])

	violation := result.fail(
		rego.metadata.chain(),
		object.union(
			result.location(key_term),
			{"description": sprintf("%q is an internal engine field; use data.datadog.iac and dd_output.format instead", [key_term.value])},
		),
	)
}

_internal_object_get_key(arg) := arg if {
	arg.type == "string"
	_internal(arg.value)
}

_internal_object_get_key(arg) := elem if {
	arg.type == "array"
	some elem in arg.value
	elem.type == "string"
	_internal(elem.value)
}

_internal("_dd")

_internal("$unknown")

_internal(s) if startswith(s, "_dd_")
