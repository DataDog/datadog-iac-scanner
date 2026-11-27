# METADATA
# description: Helpers shared by Contract v2 Regal structural checks
package custom.regal.lib.contract

import data.regal.ast

# True when the module defines a Contract v2 partial-set `results` rule.
v2_query if {
	some rule in ast.rules
	ast.ref_to_string(rule.head.ref) == "results"
	rule.head.key
}

call_of(node) := node.value if node.type == "call"

call_of(node) := node.terms if {
	is_array(node.terms)
	node.terms[0].type == "ref"
}

calls_in(x) := {call |
	walk(x, [_, node])
	call := call_of(node)
}

callee(call) := array.concat(ast.resolved_imports[head], [part.value | some part in array.slice(ref, 1, count(ref))]) if {
	ref := call[0].value
	head := ref[0].value
	ast.resolved_imports[head]
} else := [part.value | some part in call[0].value]
