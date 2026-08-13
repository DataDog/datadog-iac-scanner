# METADATA
# description: sprintf verb count must match the number of arguments
package custom.regal.rules.datadog["sprintf-arity"]

import data.regal.ast
import data.regal.result

# Regal's built-in bugs/sprintf-arguments-mismatch detects the same problem, but only
# says "Mismatch in `sprintf` arguments count". This reports the actual counts and what
# the mismatch does to the rule, so the fix is obvious from the message alone.
report contains violation if {
	some rule_index
	some call in ast.function_calls[rule_index]

	call.name == "sprintf"

	count(call.args) == 2
	call.args[0].type == "string"
	call.args[1].type == "array"

	verbs := _verb_count(call.args[0].value)
	args := count(call.args[1].value)
	verbs != args

	violation := result.fail(
		rego.metadata.chain(),
		object.union(
			result.location(call.location),
			{"description": sprintf(
				"sprintf: format string has %d verb(s) but %d argument(s) provided. This call returns undefined and the rule body will never unify, producing zero findings",
				[verbs, args],
			)},
		),
	)
}

# Counts format verbs, treating "%%" as a literal percent rather than a verb.
_verb_count(format) := count(regex.find_n(`%[^%]`, replace(format, "%%", ""), -1))
