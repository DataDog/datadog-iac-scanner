# METADATA
# description: Custom rules must declare `package datadog`
package custom.regal.rules.datadog["package-name"]

import data.regal.ast
import data.regal.result

report contains violation if {
	ast.package_name != "datadog"

	violation := result.fail(
		rego.metadata.chain(),
		object.union(
			# The name itself, not the `package` keyword, is what has to change.
			result.location(regal.last(input["package"].path)),
			{"description": sprintf(
				"package must be 'datadog', got %q. The scanner evaluates data.datadog.DatadogPolicy.",
				[ast.package_name],
			)},
		),
	)
}
