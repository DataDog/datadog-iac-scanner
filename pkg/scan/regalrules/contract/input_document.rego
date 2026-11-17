# METADATA
# description: Terraform queries must read blocks through the Terraform library, not input.document
package custom.regal.rules.contract["input-document"]

import data.custom.regal.lib.contract as lib
import data.regal.result

report contains violation if {
	lib.terraform_query

	walk(input.rules, [_, term])
	term.type == "ref"
	term.value[0].type == "var"
	term.value[0].value == "input"
	term.value[1].value == "document"

	violation := result.fail(
		rego.metadata.chain(),
		object.union(
			result.location(term),
			{"description": concat("", [
				"input.document is the raw Terraform input. Read blocks with tf.blocks, tf.data_blocks, ",
				"tf.nested and the relation helpers, which resolve instances, references and unknown values",
			])},
		),
	)
}
