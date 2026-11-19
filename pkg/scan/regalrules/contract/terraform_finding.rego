# METADATA
# description: Results are built with common.finding, there is no tf.finding
package custom.regal.rules.contract["terraform-finding"]

import data.custom.regal.lib.contract as lib
import data.regal.result

report contains violation if {
	lib.query

	some call in lib.calls_in(input.rules)
	lib.terraform_function(call, {"finding"})

	violation := result.fail(
		rego.metadata.chain(),
		object.union(
			result.location(call[0]),
			{"description": "tf.finding does not exist: build the result with result := common.finding(subject, path, details)"},
		),
	)
}
