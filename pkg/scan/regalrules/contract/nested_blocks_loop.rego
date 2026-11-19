# METADATA
# description: Terraform rules join blocks through the relation helpers, not nested tf.blocks loops
package custom.regal.rules.contract["nested-blocks-loop"]

import data.custom.regal.lib.contract as lib
import data.regal.config
import data.regal.result
import data.regal.util

# Reported as a warning unless the configuration sets a level.
default _level := "warning"

_level := config.rules.contract["nested-blocks-loop"].level

report contains violation if {
	lib.terraform_query

	some rule in input.rules
	loops := [call |
		walk(rule, [_, node])
		call := lib.iterated_call(node)
		lib.terraform_function(call, lib.block_functions)
	]
	sorted := sort([[loc.row, loc.col, i] |
		some i, call in loops
		loc := util.to_location_object(call[0].location)
	])
	count({[row, col] | some [row, col, _] in sorted}) > 1

	second := loops[sorted[1][2]]

	violation := object.union(
		result.fail(
			rego.metadata.chain(),
			object.union(
				result.location(second[0]),
				{"description": concat("", [
					"nested loops over tf.blocks join blocks by hand. Use tf.related, tf.targets or tf.referrers, ",
					"which follow references and literal matches and report an incomplete answer",
				])},
			),
		),
		{"level": _level},
	)
}
