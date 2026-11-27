package datadog.iac

import rego.v1

# Platform-agnostic Contract v2 facade backed by explicit 4-state provenance
# (Known, Unknown, Null, Absent). Top-level resources and nested block views
# returned by iac.blocks(...) carry full 4-state provenance at any nesting depth
# so rules express absence, exemptions, and collection checks without manual
# unknown guards.

_digits := {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}

_norm_path(path) := [path] if is_string(path)

_norm_path(path) := path if is_array(path)

_escape_str(s) := strings.replace_n({"\\": "\\\\", ".": "\\."}, s) if {
	contains(s, "\\")
} else := strings.replace_n({".": "\\."}, s) if {
	contains(s, ".")
} else := s

_escape_step(s) := concat("", ["\\", _escape_str(s)]) if {
	is_string(s)
	count(s) > 0
	substring(s, 0, 1) in _digits
} else := _escape_str(s) if {
	is_string(s)
} else := format_int(s, 10) if {
	is_number(s)
}

path_key(path) := _escape_step(path) if {
	is_string(path)
} else := _escape_step(path[0]) if {
	is_array(path)
	count(path) == 1
} else := concat(".", [_escape_step(s) | some s in _norm_path(path)])

_target_obj(res) := _view_data(res) if {
	is_object(res)
	is_array(object.get(res, "_dd_prefix", null))
} else := attrs if {
	is_object(res)
	attrs := object.get(res, "attributes", null)
	is_object(attrs)
} else := res if {
	is_object(res)
}

_root_res(res) := r if {
	is_object(res)
	r := object.get(res, "_dd_root", null)
	is_object(r)
} else := res

_state(res) := s if {
	is_object(res)
	s := object.get(res, "_dd_parent_state", null)
	is_object(s)
} else := object.get(res, "state", {})

_prefix(res) := p if {
	is_object(res)
	p := object.get(res, "_dd_prefix", null)
	is_array(p)
} else := []

_full_path(res, path) := array.concat(p, _norm_path(path)) if {
	is_object(res)
	p := object.get(res, "_dd_prefix", null)
	is_array(p)
	count(p) > 0
} else := _norm_path(path)

# Full resource-relative path for a nested block view plus rel_path.
path_of(res, rel_path) := _full_path(res, rel_path)

_has_ancestor_key(set_obj, full_path) if {
	set_obj[""] == true
} else if {
	count(full_path) == 1
	set_obj[_escape_step(full_path[0])] == true
} else if {
	count(full_path) > 1
	some n in numbers.range(1, count(full_path))
	set_obj[path_key(array.slice(full_path, 0, n))] == true
}

_has_descendant_flag(flags, full_path) if {
	count(flags) > 0
	prefix := path_key(full_path)
	prefix == ""
	some key, flag in flags
	flag == true
	key != ""
} else if {
	count(flags) > 0
	prefix := concat("", [path_key(full_path), "."])
	some key, flag in flags
	flag == true
	startswith(key, prefix)
}

_has_descendant_unknown(res, path) if {
	unk := object.get(_state(res), "unknown", null)
	count(unk) > 0
	_has_descendant_flag(unk, _full_path(res, path))
}

_is_incomplete_collection(res, path) if {
	inc := object.get(_state(res), "incomplete_collections", null)
	count(inc) > 0
	inc[path_key(_full_path(res, path))] == true
}

_inc_at_or_below(inc, full) if {
	inc[path_key(full)] == true
} else if {
	_has_descendant_flag(inc, full)
}

_collection_has_unknowns(res, path) if {
	inc := object.get(_state(res), "incomplete_collections", null)
	count(inc) > 0
	_inc_at_or_below(inc, _full_path(res, path))
} else if {
	_has_descendant_unknown(res, path)
}

_has_incomplete_collection_ancestor(res, path) if {
	inc := object.get(_state(res), "incomplete_collections", null)
	count(inc) > 0
	_has_ancestor_key(inc, _full_path(res, path))
}

_scope_complete(res) if {
	root := _root_res(res)
	is_object(root)
	complete := object.get(root, "scope_complete", object.get(input, "scope_complete", true))
	complete == true
}

# True when path (or an ancestor) has explicit unknown-state provenance.
is_unknown(res, path) if {
	is_object(res)
	unk := object.get(_state(res), "unknown", null)
	count(unk) > 0
	_has_ancestor_key(unk, _full_path(res, path))
}

# True when path (or an ancestor) was explicitly set to null.
is_null_value(res, path) if {
	is_object(res)
	nulls := object.get(_state(res), "null", null)
	count(nulls) > 0
	not is_unknown(res, path)
	_has_ancestor_key(nulls, _full_path(res, path))
} else if {
	is_object(res)
	null_paths := object.get(_state(res), "null_paths", null)
	count(null_paths) > 0
	not is_unknown(res, path)
	full := _full_path(res, path)
	some null_path in null_paths
	_path_is_at_or_below(full, null_path)
}

# True when path was written in source configuration.
is_written(res, path) if {
	is_object(res)
	written := object.get(_state(res), "written", null)
	count(written) > 0
	written[path_key(_full_path(res, path))] == true
}

_raw_get(res, path) := v if {
	v := object.get(_target_obj(res), _norm_path(path), null)
	v != null
}

# Returns the concrete value at path when known; undefined for unknown, null,
# or absent values. Unknown list slots are identified by their indexed state.
get(res, path) := v if {
	v := _raw_get(res, path)
	not is_unknown(res, path)
	not is_null_value(res, path)
}

is_known(res, path) if {
	_ := get(res, path)
}

all_known(res, paths) if {
	every p in paths {
		is_known(res, p)
	}
}

# True when path is provably absent (not known, not unknown, not explicit null).
is_absent(res, path) if {
	is_object(res)
	not is_known(res, path)
	not is_unknown(res, path)
	not _has_descendant_unknown(res, path)
	not _has_incomplete_collection_ancestor(res, path)
	not is_null_value(res, path)
}

# True when path is provably absent or explicitly null (provider default applies).
# Always false when unknown (at any nesting depth).
is_unset(res, path) if {
	is_object(res)
	not is_known(res, path)
	not is_unknown(res, path)
	not _has_descendant_unknown(res, path)
	not _has_incomplete_collection_ancestor(res, path)
}

read(res, path) := {"state": "unknown"} if {
	is_unknown(res, path)
} else := {"state": "null"} if {
	is_null_value(res, path)
} else := {"state": "known", "value": v} if {
	v := get(res, path)
} else := {"state": "absent"} if {
	is_absent(res, path)
} else := {"state": "unknown"}

# 3-valued boolean, equality, and exemption predicates (fail-closed on unknowns).
is_true(res, path) if {
	v := get(res, path)
	_truthy(v)
}

is_false(res, path) if {
	v := get(res, path)
	_falsy(v)
}

_truthy(true)

_truthy("true")

_truthy("1")

_falsy(false)

_falsy("false")

_falsy("0")

_is_collection(v) if is_array(v)

_is_collection(v) if is_object(v)

_value_complete(res, path, v) if {
	not _is_collection(v)
} else if {
	not _collection_has_unknowns(res, path)
}

# A path has complete information when no unknown value or open collection
# occurs at it or below it. Known absence and explicit null are complete states.
# Use before negating a custom predicate over a compound value.
is_complete(res, path) if {
	is_object(res)
	not is_unknown(res, path)
	not _collection_has_unknowns(res, path)
}

equals(res, path, expected) if {
	v := get(res, path)
	_value_complete(res, path, v)
	v == expected
}

# 3-valued inequality: true when known and != expected, OR provably absent/null.
# Always false when unknown or comparing a partially-unknown collection.
not_equals(res, path, expected) if {
	v := get(res, path)
	_value_complete(res, path, v)
	not _has_incomplete_collection_ancestor(res, path)
	v != expected
} else if {
	is_unset(res, path)
}

# 3-valued non-membership exemption: true when known and not in disallowed set/array,
# OR provably absent/null. Always false when unknown.
not_in(res, path, values) if {
	v := get(res, path)
	_value_complete(res, path, v)
	not _has_incomplete_collection_ancestor(res, path)
	not v in values
} else if {
	is_unset(res, path)
}

# Stateful nested block list accessor: always returns an array of block views
# carrying parent 4-state provenance and path prefix for iac.path_of(...).
# For array-form blocks (HCL / Plan JSON), the prefix includes the element index
# `[name, i]`; for object-form `.tf.json` blocks parsed as an attribute map, the
# prefix stays `[name]` so State.Unknown / State.Null / Source.Ranges paths match.
_raw_block_field(res, name) := _target_obj(res)[name]

_view_data(res) := value if {
	value := object.get(res, "_dd_value", null)
	is_object(value)
} else := object.remove(res, _view_metadata_keys)

_view_metadata_keys := {"_dd_value", "_dd_parent_state", "_dd_prefix", "_dd_root"}

_path_is_at_or_below(full_path, prefix) if {
	count(prefix) <= count(full_path)
	array.slice(full_path, 0, count(prefix)) == prefix
}

_json_null_paths(doc) := [path |
	[path, value] := walk(doc)
	value == null
]

blocks(res, name) := [object.union(object.remove(elem, _view_metadata_keys), {
	"_dd_value": elem,
	"_dd_parent_state": _state(res),
	"_dd_prefix": array.concat(_prefix(res), [name, i]),
	"_dd_root": _root_res(res),
}) |
	list := _raw_block_field(res, name)
	is_array(list)
	some i, elem in list
	is_object(elem)
	not is_unknown(res, array.concat([name], [i]))
	not is_null_value(res, array.concat([name], [i]))
] if {
	is_array(_raw_block_field(res, name))
} else := [object.union(object.remove(obj, _view_metadata_keys), {
	"_dd_value": obj,
	"_dd_parent_state": _state(res),
	"_dd_prefix": array.concat(_prefix(res), [name]),
	"_dd_root": _root_res(res),
})] if {
	obj := _raw_block_field(res, name)
	is_object(obj)
	not is_unknown(res, [name])
	not is_null_value(res, [name])
} else := []

# Object elements are stateful views, just like iac.blocks. Returning a raw
# partial object would turn an unknown child into an apparently absent field.
_item_view(res, path, i, v) := object.union(object.remove(v, _view_metadata_keys), {
	"_dd_value": v,
	"_dd_parent_state": _state(res),
	"_dd_prefix": array.concat(_full_path(res, path), [i]),
	"_dd_root": _root_res(res),
}) if {
	is_object(v)
}

_item_view(_, _, _, v) := v if not is_object(v)

# Known elements, skipping null and unknown slots. Use complete_items for
# whole-collection comparisons; read object elements through the iac facade.
known_items(res, path) := [_item_view(res, path, i, v) |
	list := get(res, path)
	is_array(list)
	some i, v in list
	v != null
	not is_unknown(res, array.concat(_norm_path(path), [i]))
	not is_null_value(res, array.concat(_norm_path(path), [i]))
]

# [index, value] pairs preserving source indices and object state provenance.
indexed_items(res, path) := [[i, _item_view(res, path, i, v)] |
	list := get(res, path)
	is_array(list)
	some i, v in list
	v != null
	not is_unknown(res, array.concat(_norm_path(path), [i]))
	not is_null_value(res, array.concat(_norm_path(path), [i]))
]

# Returns an array ONLY when every element is known and the collection is closed
# (safe for universal checks like `every`, `sort`, or negated membership).
complete_items(res, path) := list if {
	list := get(res, path)
	is_array(list)
	not _collection_has_unknowns(res, path)
}

# True when k is a direct child of prefix (escaped dots stay inside one key segment).
_has_unescaped_dot(s) if {
	cleaned := strings.replace_n({"\\\\": "_", "\\.": "_"}, s)
	contains(cleaned, ".")
}

_is_direct_child_key(prefix, k) if {
	startswith(k, prefix)
	rest := substring(k, count(prefix), count(k) - count(prefix))
	not _has_unescaped_dot(rest)
}

_known_escaped_keys(obj) := {_escape_step(k) | some k, _ in obj}

_is_numeric_path_step(s) if {
	startswith(s, "\\")
	not startswith(s, "\\\\")
	count(s) > 1
	substring(s, 1, 1) in _digits
}

_decode_path_step(s) := strings.replace_n({"\\\\": "\\", "\\.": "."}, substring(s, 1, count(s) - 1)) if {
	_is_numeric_path_step(s)
} else := strings.replace_n({"\\\\": "\\", "\\.": "."}, s)

_object_child_prefix(path) := concat("", [path_key(path), "."]) if count(path) > 0

else := ""

_extra_object_keys(res, path, v) := {key |
	prefix := _object_child_prefix(_full_path(res, path))
	known := _known_escaped_keys(v)
	some state_map in [object.get(_state(res), "unknown", {}), object.get(_state(res), "null", {})]
	some k, flag in state_map
	flag == true
	_is_direct_child_key(prefix, k)
	escaped_key := substring(k, count(prefix), count(k) - count(prefix))
	not escaped_key in known
	key := _decode_path_step(escaped_key)
}

# Returns the exact known length of a closed array or object (including a closed
# list containing unknown elements, e.g. ["a", var.x] -> 2, and a map with known
# keys and unknown values, e.g. { Env = var.env } -> 1). Undefined when the
# collection itself is unknown or its size is incomplete (e.g. unresolved dynamic
# block or unknown map key).
length(res, path) := n if {
	v := get(res, path)
	is_array(v)
	not _is_incomplete_collection(res, path)
	n := count(v)
} else := n if {
	v := get(res, path)
	is_object(v)
	not _is_incomplete_collection(res, path)
	n := count(v) + count(_extra_object_keys(res, path, v))
}

# Exact keys for a closed object, including children whose values are unknown
# or null. Undefined when the object itself is unknown, null, open, or not an object.
object_keys(res, path) := keys if {
	v := get(res, path)
	is_object(v)
	not is_null_value(res, path)
	not _is_incomplete_collection(res, path)
	keys := object.keys(v) | _extra_object_keys(res, path, v)
}

# True ONLY when the collection at path is provably empty AND complete.
is_empty(res, path) if {
	is_object(res)
	not is_unknown(res, path)
	not _collection_has_unknowns(res, path)
	_is_empty_collection_or_unset(res, path)
}

_is_empty_collection_or_unset(res, path) if {
	is_unset(res, path)
} else if {
	v := get(res, path)
	is_array(v)
	count(v) == 0
} else if {
	v := get(res, path)
	is_object(v)
	length(res, path) == 0
}

# Ordered string template chunks. Unknown chunks retain their positions with
# known=false; concrete strings have one known chunk.
template_parts(res, path) := parts if {
	parts := object.get(_root_res(res), ["derived", "template_parts", path_key(_full_path(res, path))], null)
	is_array(parts)
} else := [{"known": true, "value": value}] if {
	value := get(res, path)
	is_string(value)
} else := [{"known": true, "value": value}] if {
	value := _json_leaf_string(res, path)
}

# Read a JSON string leaf through its original attribute path. JSON view paths
# remain document-relative; callers requesting source chunks use the resource.
_json_leaf_string(res, path) := value if {
	root := _root_res(res)
	full := _full_path(res, path)
	prefixes := {size |
		some size in numbers.range(1, count(full))
		key := path_key(array.slice(full, 0, size))
		object.get(root, ["derived", "json", key], null) != null
	}
	boundary := max(prefixes)
	attribute := array.slice(full, 0, boundary)
	doc := object.get(root, ["derived", "json", path_key(attribute)], null)
	is_object(doc)
	value := get(_wrap_json_doc(root, attribute, doc), array.slice(full, boundary, count(full)))
	is_string(value)
}

# Demand-derived embedded JSON document (handles jsonencode, heredocs,
# data.aws_iam_policy_document, and concrete JSON strings uniformly).
# Object documents carry derived.json_unknown provenance so iac.blocks(...) and
# iac.is_unset(...) / iac.is_empty(...) preserve unknowns on nested sub-objects
# (such as IAM Statements and Conditions) without manual unknown guards.
_wrap_json_doc(res, path, doc) := object.union(object.remove(doc, _view_metadata_keys), {
	"_dd_value": doc,
	"_dd_parent_state": {
		"unknown": object.get(_root_res(res), ["derived", "json_unknown", path_key(_full_path(res, path))], {}),
		"null_paths": _json_null_paths(doc),
	},
	"_dd_prefix": [],
	"_dd_root": _root_res(res),
}) if {
	is_object(doc)
} else := doc

json_doc(res, path) := _wrap_json_doc(res, path, doc) if {
	doc := object.get(_root_res(res), ["derived", "json", path_key(_full_path(res, path))], null)
	doc != null
} else := doc if {
	v := get(res, path)
	is_string(v)
	raw := json.unmarshal(v)
	doc := _wrap_json_doc(res, path, raw)
}

json_refs(res, path, leaf_path) := [ref |
	rmap := object.get(_root_res(res), ["derived", "json_refs", path_key(_full_path(res, path))], {})
	prefix := _leaf_key(leaf_path)
	some k, list in rmap
	_matches_leaf_prefix(k, prefix)
	some ref in list
]

json_has_unknown(res, path, leaf_path) if {
	unk := object.get(_root_res(res), ["derived", "json_unknown", path_key(_full_path(res, path))], {})
	prefix := _leaf_key(leaf_path)
	some k, _ in unk
	_matches_leaf_prefix(k, prefix)
}

_leaf_key(p) := p if is_string(p)

_leaf_key(p) := path_key(p) if is_array(p)

_matches_leaf_prefix(k, prefix) if k == prefix

_matches_leaf_prefix(k, prefix) if startswith(k, concat("", [prefix, "."]))

_matches_leaf_prefix(k, prefix) if {
	k != ""
	startswith(prefix, concat("", [k, "."]))
}

_matches_leaf_prefix("", _)

_matches_leaf_prefix(_, "")

# Intra-unit relation helpers (with per-resource scope_complete & explicit completeness).
_by_id(id) := object.get(input, ["by_id", id], null)

_resolve_ids(ids) := [r |
	some id in ids
	r := _by_id(id)
	r != null
]

_target_entry(res, path) := object.get(_root_res(res), ["relations", "targets", path_key(_full_path(res, path))], {"ids": [], "complete": true})

targets(res, path) := _resolve_ids(object.get(_target_entry(res, path), "ids", []))

targets_complete(res, path) if {
	_scope_complete(res)
	object.get(_target_entry(res, path), "complete", true) == true
}

_related_entry(res, comp_type, attr) := object.get(_root_res(res), ["relations", "related", comp_type, path_key(attr)], {"ids": [], "complete": true})

related(res, comp_type, attr) := _resolve_ids(object.get(_related_entry(res, comp_type, attr), "ids", []))

no_related(res, comp_type, attr) if {
	_scope_complete(res)
	entry := _related_entry(res, comp_type, attr)
	object.get(entry, "complete", true) == true
	count(object.get(entry, "ids", [])) == 0
}

referrers(res, paths) := [r |
	ids := {id |
		some p in paths
		entry := object.get(_root_res(res), ["relations", "referrers", path_key(p)], {})
		some id in object.get(entry, "ids", [])
	}
	some id in ids
	r := _by_id(id)
	r != null
]

no_referrers(res, paths) if {
	_scope_complete(res)
	every p in paths {
		entry := object.get(_root_res(res), ["relations", "referrers", path_key(p)], {"ids": [], "complete": true})
		object.get(entry, "complete", true) == true
		count(object.get(entry, "ids", [])) == 0
	}
}

no_resources(res_type) if {
	object.get(input, "scope_complete", true) == true
	count(object.get(input, ["resources", res_type], [])) == 0
}

# Targets selected by the target attribute read (for example name versus arn).
targets_via(res, path, attr) := _resolve_ids(object.get(_root_res(res), ["relations", "targets_via", path_key(_full_path(res, path)), _leaf_key(attr), "ids"], []))

targets_via_complete(res, path, attr) if {
	targets_complete(res, path)
	object.get(_root_res(res), ["relations", "targets_via", path_key(_full_path(res, path)), _leaf_key(attr), "complete"], true) == true
}

related_complete(res, comp_type, attr) if {
	_scope_complete(res)
	object.get(_related_entry(res, comp_type, attr), "complete", true) == true
}

referrers_complete(res, paths) if {
	_scope_complete(res)
	every p in paths {
		object.get(_root_res(res), ["relations", "referrers", path_key(p), "complete"], true) == true
	}
}
