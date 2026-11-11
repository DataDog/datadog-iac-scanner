# METADATA
# description: Helpers shared by the rule contract checks
package custom.regal.lib.contract

import data.regal.ast

terraform_library := ["data", "generic", "terraform"]

# Rules are in package datadog; libraries (package generic.*) are exempt.
query if ast.package_name == "datadog"

terraform_query if {
	query
	some path in ast.resolved_imports
	path == terraform_library
}

terraform_query if {
	query
	regex.match(`(^|/)queries/terraform/`, input.regal.file.name)
}

# A call is [callee ref, args...], from a call term or a call expression.
call_of(node) := node.value if node.type == "call"

call_of(node) := node.terms if {
	is_array(node.terms)
	node.terms[0].type == "ref"
}

calls_in(x) := {call |
	walk(x, [_, node])
	call := call_of(node)
}

# The callee path of a call, with an imported alias replaced by its path.
callee(call) := array.concat(ast.resolved_imports[head], [part.value | some part in array.slice(ref, 1, count(ref))]) if {
	ref := call[0].value
	head := ref[0].value
	ast.resolved_imports[head]
} else := [part.value | some part in call[0].value]

terraform_function(call, names) if {
	path := callee(call)
	count(path) == 4
	array.slice(path, 0, 3) == terraform_library
	path[3] in names
}

block_functions := {"blocks", "data_blocks", "ephemeral_blocks"}

# The domain of an iteration over a call: `some x in f(...)`, `some k, x in f(...)`
# or `f(...)[_]`.
iterated_call(node) := domain if {
	call := call_of(node)
	callee(call) in {["internal", "member_2"], ["internal", "member_3"]}
	last := call[count(call) - 1]
	domain := call_of(last)
}

iterated_call(node) := call_of(node.value[0]) if {
	node.type == "ref"
	count(node.value) > 1
}
