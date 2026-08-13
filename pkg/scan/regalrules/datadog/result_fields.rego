# METADATA
# description: DatadogPolicy results must set every required finding field
package custom.regal.rules.datadog["result-fields"]

import data.regal.ast
import data.regal.result

_required := {"documentId", "resourceType", "resourceName", "searchKey"}

report contains violation if {
	some rule in ast.rules
	ast.ref_to_string(rule.head.ref) == "DatadogPolicy"

	some expr in rule.body
	expr.terms[0].value[0].value == "assign"
	expr.terms[1].type == "var"
	expr.terms[1].value == "result"
	expr.terms[2].type == "object"

	present := {key |
		some pair in expr.terms[2].value
		pair[0].type == "string"
		key := pair[0].value
	}

	some missing in (_required - present)

	violation := result.fail(
		rego.metadata.chain(),
		object.union(
			result.location(expr.terms[1]),
			{"description": sprintf(
				"result object is missing required field %q. Findings without this field will have empty values in scan output",
				[missing],
			)},
		),
	)
}
