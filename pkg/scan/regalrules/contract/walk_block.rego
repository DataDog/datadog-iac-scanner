# METADATA
# description: Terraform rules must not walk a whole block
package custom.regal.rules.contract["walk-block"]

import data.custom.regal.lib.contract as lib
import data.regal.ast
import data.regal.result

report contains violation if {
	lib.terraform_query

	some rule in input.rules
	blocks := _block_vars(rule)

	some call in lib.calls_in(rule)
	lib.callee(call) == ["walk"]
	_whole_block(call[1], blocks)

	violation := result.fail(
		rego.metadata.chain(),
		object.union(
			result.location(call[0]),
			{"description": concat("", [
				"walk over a whole block also visits attributes the rule does not check and the engine metadata. ",
				"Walk the attribute the rule checks, or use tf.json for a policy document",
			])},
		),
	)
}

_whole_block(arg, blocks) if {
	arg.type == "var"
	arg.value in blocks
}

_whole_block(arg, _) if {
	arg.type == "var"
	arg.value == "input"
}

_whole_block(arg, _) if {
	arg.type == "ref"
	arg.value[0].value == "input"
	count(arg.value) <= 2
}

# Variables bound to blocks: some b in tf.<f>(...), some _, b in tf.<f>(...),
# b := tf.<f>(...) and b := tf.<f>(...)[_].
_block_vars(rule) := {name |
	walk(rule, [_, node])
	name := _bound_block(node)
}

_bound_block(node) := var.value if {
	call := lib.call_of(node)
	lib.callee(call) in {["internal", "member_2"], ["internal", "member_3"]}
	_library_call(call[count(call) - 1])
	var := call[count(call) - 2]
	var.type == "var"
}

_bound_block(node) := node.terms[1].value if {
	ast.is_assignment(node.terms[0])
	node.terms[1].type == "var"
	_library_term(node.terms[2])
}

_library_term(term) if _library_call(term)

_library_term(term) if {
	term.type == "ref"
	_library_call(term.value[0])
}

_library_call(term) if {
	call := lib.call_of(term)
	path := lib.callee(call)
	array.slice(path, 0, 3) == lib.terraform_library
}
