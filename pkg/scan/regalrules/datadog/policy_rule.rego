# METADATA
# description: Rules must define either `DatadogPolicy` (legacy) or `results` (Contract v2)
package custom.regal.rules.datadog["policy-rule"]

import data.regal.ast
import data.regal.result

_has_entry(name) if {
	some rule in ast.rules
	ast.ref_to_string(rule.head.ref) == name
}

report contains violation if {
	not _has_entry("DatadogPolicy")
	not _has_entry("results")

	violation := result.fail(
		rego.metadata.chain(),
		object.union(
			_location,
			{"description": concat("", [
				"no 'DatadogPolicy' or 'results' rule found. Define data.datadog.results ",
				"(Contract v2) or data.datadog.DatadogPolicy (legacy)",
			])},
		),
	)
}

report contains violation if {
	_has_entry("DatadogPolicy")
	_has_entry("results")

	violation := result.fail(
		rego.metadata.chain(),
		object.union(
			_location,
			{"description": "rule defines both 'DatadogPolicy' and 'results'; use only 'results' for Contract v2 or 'DatadogPolicy' for legacy"},
		),
	)
}

report contains violation if {
	some rule in ast.rules
	ast.ref_to_string(rule.head.ref) == "results"
	not rule.head.key

	violation := result.fail(
		rego.metadata.chain(),
		object.union(
			result.location(rule.head),
			{"description": "'results' must be a partial set rule (`results contains result if { ... }`), not a single-value assignment"},
		),
	)
}

# Point at the misnamed rule when there is one, since that is what needs renaming.
_location := result.location(ast.rules[0].head) if count(ast.rules) > 0

_location := result.location(input["package"]) if count(ast.rules) == 0
