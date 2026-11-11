# METADATA
# description: Queries must not name engine fields such as _dd, _dd_meta or _dd_id
package custom.regal.rules.contract["internal-fields"]

import data.custom.regal.lib.contract as lib
import data.regal.result

report contains violation if {
	lib.query

	walk(input.rules, [_, term])
	term.type == "string"
	_internal(term.value)

	violation := result.fail(
		rego.metadata.chain(),
		object.union(
			result.location(term),
			{"description": sprintf(
				"%q is an engine field: read values through the platform library and build results with common.finding",
				[term.value],
			)},
		),
	)
}

_internal("_dd")

_internal(s) if startswith(s, "_dd_")
