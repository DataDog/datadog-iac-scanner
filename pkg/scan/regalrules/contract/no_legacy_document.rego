# METADATA
# description: Contract v2 rules must read input.resources, not legacy input.document
package custom.regal.rules.contract["no-legacy-document"]

import data.custom.regal.lib.contract as lib
import data.regal.result

report contains violation if {
	lib.v2_query

	walk(input.rules, [_, term])
	term.type == "ref"
	term.value[0].type == "var"
	term.value[0].value == "input"
	term.value[1].value == "document"

	violation := result.fail(
		rego.metadata.chain(),
		object.union(
			result.location(term),
			{"description": "Contract v2 rules must read input.resources.<type> instead of legacy input.document"},
		),
	)
}

report contains violation if {
	lib.v2_query

	some imp in input.imports
	imp.path.type == "ref"
	imp.path.value[0].value == "input"
	imp.path.value[1].value == "document"

	violation := result.fail(
		rego.metadata.chain(),
		object.union(
			result.location(imp),
			{"description": "Contract v2 rules must read input.resources.<type> instead of importing legacy input.document"},
		),
	)
}
