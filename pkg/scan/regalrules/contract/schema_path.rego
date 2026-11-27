# METADATA
# description: Validate Contract v2 Terraform resource types and literal facade paths against an optional generated schema index
package custom.regal.rules.contract["schema-path"]

import data.custom.regal.lib.contract as lib
import data.regal.result

_schema_index := data.custom.regal.rules.contract.schemadata.index

report contains violation if {
	_schema_enabled
	some violation in _some_schema_type_error
}

report contains violation if {
	_schema_enabled
	some violation in _some_data_source_type_error
}

report contains violation if {
	_schema_enabled
	some violation in _some_schema_path_error
}

report contains violation if {
	_schema_enabled
	some violation in _some_related_type_error
}

report contains violation if {
	_schema_enabled
	_some_missing_suppression_reason
	rule := input.rules[0]
	violation := result.fail(
		rego.metadata.chain(),
		object.union(
			result.location(rule),
			{"description": "A schema-path suppression must include a non-empty reason (for example, '# regal ignore:schema-path # reason: provider-version compatibility')."},
		),
	)
}

_schema_enabled if is_object(_schema_index)

# Emit one non-failing Regal notice per module with a machine-readable coverage summary.
report contains violation if {
	_schema_enabled
	entries := _schema_call_entries
	count(entries) > 0
	checked := count({entry | some entry in entries; _checked_schema_call(entry)})
	unchecked := count(entries) - checked
	percent := round((100 * unchecked) / count(entries))
	rule := input.rules[0]
	violation := object.union(
		result.fail(rego.metadata.chain(), object.union(
			result.location(rule),
			{"description": sprintf("schema-path coverage: checked=%d unchecked=%d unchecked_percent=%d", [checked, unchecked, percent])},
		)),
		{"title": "schema-path-coverage", "level": "notice"},
	)
}

_schema_call_entries := {{"rule": rule, "call": call, "facade": facade} |
	some rule in input.rules
	some call in lib.calls_in(rule.body)
	callee := lib.callee(call)
	facade := _facade_path(call, callee)
}

_checked_schema_call(entry) if {
	binding := _call_resource_binding(entry.rule, entry.call, entry.facade.resource_arg)
	_path_is_static(entry.call[entry.facade.path_arg])
	type := object.get(entry.facade, "related_type", binding.type)
	object.get(_schema_index, type, null) != null
}

_path_is_static(term) if term.type == "string"

_path_is_static(term) if {
	term.type == "array"
	every step in term.value {
		step.type in {"string", "number"}
	}
}

_some_schema_type_error contains violation if {
	some rule in input.rules
	some term in _resource_type_refs(rule.body)
	type := _resource_type(term)
	object.get(_schema_index, type, null) == null
	not _schema_path_suppressed(term)
	violation := result.fail(
		rego.metadata.chain(),
		object.union(
			result.location(term),
			{"description": sprintf("Terraform resource or data-source type %q is not present in the generated schema index.", [type])},
		),
	)
}

_some_data_source_type_error contains violation if {
	some rule in input.rules
	some term in _data_source_type_refs(rule.body)
	type := _resource_type(term)
	object.get(_schema_index, type, null) == null
	not _schema_path_suppressed(term)
	violation := result.fail(
		rego.metadata.chain(),
		object.union(
			result.location(term),
			{"description": sprintf("Terraform data-source type %q is not present in the generated schema index.", [type])},
		),
	)
}

_some_related_type_error contains violation if {
	some rule in input.rules
	some call in lib.calls_in(rule.body)
	callee := lib.callee(call)
	_is_iac_facade(callee)
	callee[3] in {"related", "no_related", "related_complete"}
	call[2].type == "string"
	type := call[2].value
	object.get(_schema_index, type, null) == null
	not _schema_path_suppressed(call[2])
	violation := result.fail(
		rego.metadata.chain(),
		object.union(
			result.location(call[2]),
			{"description": sprintf("Related Terraform resource or data-source type %q is not present in the generated schema index.", [type])},
		),
	)
}

_some_schema_path_error contains violation if {
	some rule in input.rules
	some call in lib.calls_in(rule.body)
	callee := lib.callee(call)
	facade := _facade_path(call, callee)
	binding := _call_resource_binding(rule, call, facade.resource_arg)
	type := object.get(facade, "related_type", binding.type)
	trie := object.get(_schema_index, type, null)
	trie != null
	path := array.concat(binding.prefix, facade.path)
	not _schema_path_suppressed(call)
	not _schema_path_exists(trie, path)
	violation := result.fail(
		rego.metadata.chain(),
		object.union(
			result.location(call[facade.path_arg]),
			{"description": sprintf("Terraform path %q does not exist for resource or data-source type %q in the generated schema index.", [concat(".", [sprintf("%v", [step]) | some step in path]), type])},
		),
	)
}

_some_missing_suppression_reason if {
	some line in input.regal.file.lines
	contains(line, "regal ignore:schema-path")
	not regex.match(`(?s).*#\s*reason:\s*\S+.*`, line)
}

_schema_path_suppressed(term) if {
	row := result.location(term).location.row
	row > 1
	line := input.regal.file.lines[row - 2]
	contains(line, "regal ignore:schema-path")
	regex.match(`(?s).*#\s*reason:\s*\S+.*`, line)
}

_resource_type_refs(body) := {term |
	walk(body, [_, term])
	term.type == "ref"
	ref := term.value
	count(ref) > 2
	ref[0].type == "var"
	ref[0].value == "input"
	ref[1].type == "string"
	ref[1].value == "resources"
	ref[2].type == "string"
	ref[2].value != "data"
}

_data_source_type_refs(body) := {term |
	walk(body, [_, term])
	term.type == "ref"
	ref := term.value
	count(ref) > 3
	ref[0].type == "var"
	ref[0].value == "input"
	ref[1].type == "string"
	ref[1].value == "resources"
	ref[2].type == "string"
	ref[2].value == "data"
	ref[3].type == "string"
}

_resource_type(term) := sprintf("data.%s", [ref[3].value]) if {
	term.type == "ref"
	ref := term.value
	count(ref) > 3
	ref[0].value == "input"
	ref[1].value == "resources"
	ref[2].value == "data"
	ref[3].type == "string"
}

_resource_type(term) := ref[2].value if {
	term.type == "ref"
	ref := term.value
	count(ref) > 2
	ref[0].value == "input"
	ref[1].value == "resources"
	ref[2].type == "string"
	ref[2].value != "data"
}

_facade_path(call, callee) := {"resource_arg": 1, "path_arg": 2, "path": _literal_prefix(call[2])} if {
	_is_iac_facade(callee)
	callee[3] in {"get", "is_unset", "is_absent", "is_complete", "equals", "not_equals", "in", "not_in", "is_true", "is_false", "is_unknown", "is_known", "object_keys", "length", "is_empty", "targets", "targets_complete", "no_referrers", "referrers_complete"}
}

_facade_path(call, callee) := {"resource_arg": 1, "path_arg": 3, "path": [call[3].value], "related_type": call[2].value} if {
	_is_iac_facade(callee)
	callee[3] in {"related", "no_related", "related_complete"}
	call[2].type == "string"
	call[3].type == "string"
}

_facade_path(call, callee) := {"resource_arg": 1, "path_arg": 2, "path": _literal_prefix(call[2])} if {
	_is_terraform_facade(callee)
	callee[3] in {"computed", "value_view", "source_is_null"}
}

_facade_path(call, callee) := {"resource_arg": 1, "path_arg": 2, "path": [call[2].value]} if {
	_is_iac_facade(callee)
	callee[3] == "blocks"
	call[2].type == "string"
}

_is_iac_facade(callee) if {
	count(callee) == 4
	array.slice(callee, 0, 3) == ["data", "datadog", "iac"]
}

_is_terraform_facade(callee) if {
	count(callee) == 4
	array.slice(callee, 0, 3) == ["data", "datadog", "terraform"]
}

_call_resource_binding(rule, call, arg) := binding if {
	term := call[arg]
	binding := _resource_binding(rule, term)
}

_resource_binding(rule, term) := {"type": type, "prefix": []} if {
	type := _input_resource_type(term)
}

_resource_binding(rule, term) := {"type": type, "prefix": []} if {
	term.type == "var"
	type := _input_resource_variable(rule, term.value)
}

_resource_binding(rule, term) := {"type": type, "prefix": [view.block]} if {
	term.type == "var"
	view := _block_view_variable(rule, term.value)
	type := _input_resource_variable(rule, view.base)
}

_resource_binding(rule, term) := {"type": type, "prefix": view.path} if {
	term.type == "var"
	view := _value_view_variable(rule, term.value)
	type := _input_resource_variable(rule, view.base)
}

_input_resource_variable(rule, name) := type if {
	some call in lib.calls_in(rule.body)
	lib.callee(call) == ["internal", "member_2"]
	call[1].type == "var"
	call[1].value == name
	type := _input_resource_type(call[2])
}

_input_resource_variable(rule, name) := type if {
	some call in lib.calls_in(rule.body)
	lib.callee(call) == ["internal", "member_3"]
	call[2].type == "var"
	call[2].value == name
	type := _input_resource_type(call[3])
}

_input_resource_variable(rule, name) := type if {
	some call in lib.calls_in(rule.body)
	lib.callee(call) == ["assign"]
	call[1].type == "var"
	call[1].value == name
	type := _input_resource_type(call[2])
}

_input_resource_type(term) := type if {
	term.type == "ref"
	ref := term.value
	count(ref) > 2
	ref[0].type == "var"
	ref[0].value == "input"
	ref[1].type == "string"
	ref[1].value == "resources"
	ref[2].type == "string"
	ref[2].value == "data"
	count(ref) > 3
	ref[3].type == "string"
	type := sprintf("data.%s", [ref[3].value])
}

_input_resource_type(term) := type if {
	term.type == "ref"
	ref := term.value
	count(ref) > 2
	ref[0].type == "var"
	ref[0].value == "input"
	ref[1].type == "string"
	ref[1].value == "resources"
	ref[2].type == "string"
	ref[2].value != "data"
	type := ref[2].value
}

_block_view_variable(rule, name) := {"base": iterable.value[1].value, "block": iterable.value[2].value} if {
	some call in lib.calls_in(rule.body)
	lib.callee(call) == ["internal", "member_2"]
	call[1].type == "var"
	call[1].value == name
	iterable := call[2]
	iterable.type == "call"
	callee := lib.callee(iterable.value)
	_is_iac_facade(callee)
	callee[3] == "blocks"
	iterable.value[1].type == "var"
	iterable.value[2].type == "string"
}

_value_view_variable(rule, name) := {"base": expression.value[1].value, "path": _literal_prefix(expression.value[2])} if {
	some call in lib.calls_in(rule.body)
	lib.callee(call) == ["assign"]
	call[1].type == "var"
	call[1].value == name
	expression := call[2]
	expression.type == "call"
	callee := lib.callee(expression.value)
	_is_terraform_facade(callee)
	callee[3] == "value_view"
	expression.value[1].type == "var"
}

_literal_prefix(term) := [term.value] if term.type == "string"

_literal_prefix(term) := [step.value |
	some i, step in term.value
	step.type in {"string", "number"}
	not _has_nonliteral_before(term.value, i)
] if {
	term.type == "array"
}

_has_nonliteral_before(steps, index) if {
	some i in numbers.range(0, index - 1)
	not steps[i].type in {"string", "number"}
}

_schema_step(step) := "*" if is_number(step)

else := step

_schema_path_exists(trie, path) if {
	every i in numbers.range(1, count(path)) {
		prefix := array.slice(path, 0, i)
		schema_prefix := [_schema_step(step) | some step in prefix]
		_schema_prefix_exists(trie, schema_prefix)
	}
}

_schema_prefix_exists(trie, path) if object.get(trie, path, null) != null

_schema_prefix_exists(trie, path) if {
	count(path) > 0
	parent := array.slice(path, 0, count(path) - 1)
	wildcard := array.concat(parent, ["*"])
	object.get(trie, wildcard, null) != null
}
