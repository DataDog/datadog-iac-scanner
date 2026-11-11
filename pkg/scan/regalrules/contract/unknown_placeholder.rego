# METADATA
# description: Queries must not compare with the unknown value placeholder
package custom.regal.rules.contract["unknown-placeholder"]

import data.custom.regal.lib.contract as lib
import data.regal.result

report contains violation if {
	lib.query

	walk(input.rules, [_, term])
	term.type == "string"

	# The placeholder is "\u0000dd-unknown-<hex>"; a bare NUL is a common key separator.
	contains(term.value, "dd-unknown")

	violation := result.fail(
		rego.metadata.chain(),
		object.union(
			result.location(term),
			{"description": concat("", [
				"string holds unknown value placeholder text. The engine passes a rule whose verdict ",
				"depends on an unknown value, so rules never test for it",
			])},
		),
	)
}
