# METADATA
# description: DatadogPolicy results are bound with result := common.finding(...)
package custom.regal.rules.contract["bound-finding"]

import data.custom.regal.lib.contract as lib
import data.regal.ast
import data.regal.result

# DatadogPolicy contains common.finding(...) if { ... }
report contains violation if {
	lib.query

	some rule in _policy_rules
	rule.head.key.type == "call"

	violation := result.fail(
		rego.metadata.chain(),
		object.union(
			result.location(rule.head.key),
			{"description": concat("", [
				"bind the result in the body (result := common.finding(subject, path, details)) ",
				"and write DatadogPolicy contains result",
			])},
		),
	)
}

# result := {...} in a Terraform rule
report contains violation if {
	lib.terraform_query

	some rule in _policy_rules
	rule.head.key.type == "var"

	walk(rule.body, [_, expr])
	ast.is_assignment(expr.terms[0])
	expr.terms[1].type == "var"
	expr.terms[1].value == rule.head.key.value
	expr.terms[2].type == "object"

	violation := result.fail(
		rego.metadata.chain(),
		object.union(
			result.location(expr.terms[1]),
			{"description": concat("", [
				"build the Terraform result with common.finding(subject, path, details): ",
				"the engine derives the document, resource, search key and line from the subject",
			])},
		),
	)
}

_policy_rules contains rule if {
	some rule in ast.rules
	ast.ref_to_string(rule.head.ref) == "DatadogPolicy"
}
