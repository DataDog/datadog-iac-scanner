# METADATA
# description: Custom rules must define a `DatadogPolicy` rule
package custom.regal.rules.datadog["policy-rule"]

import data.regal.ast
import data.regal.result

report contains violation if {
	every rule in ast.rules {
		ast.ref_to_string(rule.head.ref) != "DatadogPolicy"
	}

	violation := result.fail(
		rego.metadata.chain(),
		object.union(
			_location,
			{"description": concat("", [
				"no 'DatadogPolicy' rule found. The scanner evaluates ",
				"data.datadog.DatadogPolicy so the rule must use that exact name",
			])},
		),
	)
}

# Point at the misnamed rule when there is one, since that is what needs renaming.
_location := result.location(ast.rules[0].head) if count(ast.rules) > 0

_location := result.location(input["package"]) if count(ast.rules) == 0
