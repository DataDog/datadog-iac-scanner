# METADATA
# description: Contract v2 rules must not reuse indices from compacted nested block views
package custom.regal.rules.contract["no-compacted-index-reuse"]

import data.custom.regal.lib.contract as lib
import data.regal.result

_iac_blocks := ["data", "datadog", "iac", "blocks"]

_terraform_nested := ["data", "generic", "terraform", "nested"]

report contains violation if {
	lib.v2_query

	some rule in input.rules
	scopes := _scopes(rule.body)
	some [index, scope] in _compacted_indexes(rule, scopes)
	_referenced_again(rule.body, scopes, index, scope)

	violation := result.fail(
		rego.metadata.chain(),
		object.union(
			result.location(index),
			{"description": "Do not reuse an index from iac.blocks/tf.nested; these helpers compact unknown and null slots. Use iac.path_of() on the returned block view instead."},
		),
	)
}

# Each compacted index comes with the path of the lexical scope that declares
# it: [] for the rule body, or the path of a comprehension or `every` that
# contains the declaration. Only that scope can refer to this variable.
_compacted_indexes(rule, scopes) := {[index, scope] |
	aliases := _compacted_aliases(rule.body, scopes)
	walk(rule.body, [path, node])
	call := lib.call_of(node)
	lib.callee(call) == ["internal", "member_3"]

	index := call[1]
	index.type == "var"

	_compacting_source(call[3], aliases, scopes, path)
	scope := _innermost_scope(scopes, path)
}

# Aliases of compacted views, as [name, declaring scope] pairs, so a variable
# with the same name in another scope is not mistaken for the alias.
_compacted_aliases(body, scopes) := {[alias, scope] |
	walk(body, [path, node])
	call := lib.call_of(node)
	lib.callee(call) == ["assign"]

	call[1].type == "var"
	alias := call[1].value

	_compacting_call(call[2])
	scope := _innermost_scope(scopes, path)
}

_compacting_source(term, _, _, _) if _compacting_call(term)

_compacting_source(term, aliases, scopes, path) if {
	term.type == "var"
	[term.value, _declaring_scope(scopes, path, term.value)] in aliases
}

_compacting_call(term) if {
	term.type == "call"
	lib.callee(term.value) in {_iac_blocks, _terraform_nested}
}

# Another occurrence of the same name inside the declaring scope, excluding
# nested scopes that declare their own variable with that name.
_referenced_again(body, scopes, index, scope) if {
	walk(body, [path, term])
	term.type == "var"
	term.value == index.value
	term.location != index.location

	_is_prefix(scope, path)
	not _shadowed(scopes, scope, path, index.value)
}

_shadowed(scopes, scope, path, name) if {
	some inner, names in scopes
	count(inner) > count(scope)
	_is_prefix(inner, path)
	name in names
}

# Lexical scopes nested in a rule body, as {path: names declared at the top
# level of that scope}. A comprehension scope covers its head and body; an
# `every` scope covers its key, value and body and declares its key and value.
_scopes(body) := {path: names |
	walk(body, [node_path, node])
	some [path, names] in _scope(node_path, node)
}

_comprehension_types := {"arraycomprehension", "setcomprehension", "objectcomprehension"}

_scope(node_path, node) := {[array.concat(node_path, ["value"]), _declared(node.value.body)]} if {
	node.type in _comprehension_types
}

# The domain of `every` belongs to the enclosing scope, so the key, value and
# body are separate entries.
_scope(node_path, node) := {[array.concat(node_path, ["terms", part]), names] | some part in ["key", "value", "body"]} if {
	is_object(node.terms)
	node.terms.domain
	names := {term.value |
		some key in ["key", "value"]
		term := node.terms[key]
		term.type == "var"
	} | _declared(node.terms.body)
}

# Names declared at the top level of a body by `some` or `:=`.
_declared(body) := {name |
	some expr in body
	some name in _declared_by(expr)
}

_declared_by(expr) := {term.value |
	some symbol in expr.terms.symbols
	some term in _symbol_vars(symbol)
} if {
	is_object(expr.terms)
}

_declared_by(expr) := {term.value |
	walk(expr.terms[1], [_, term])
	term.type == "var"
} if {
	is_array(expr.terms)
	lib.callee(expr.terms) == ["assign"]
}

_symbol_vars(symbol) := [symbol] if symbol.type == "var"

_symbol_vars(symbol) := [term | some term in array.slice(symbol.value, 1, count(symbol.value) - 1); term.type == "var"] if {
	symbol.type == "call"
}

_innermost_scope(scopes, path) := scope if {
	enclosing := {inner | some inner, _ in scopes; _is_prefix(inner, path)}
	depth := max({count(inner) | some inner in enclosing})
	some scope in enclosing
	count(scope) == depth
} else := []

# The innermost scope enclosing path that declares name, or the rule body.
_declaring_scope(scopes, path, name) := scope if {
	declaring := {inner | some inner, names in scopes; _is_prefix(inner, path); name in names}
	depth := max({count(inner) | some inner in declaring})
	some scope in declaring
	count(scope) == depth
} else := []

_is_prefix(prefix, path) if array.slice(path, 0, count(prefix)) == prefix
