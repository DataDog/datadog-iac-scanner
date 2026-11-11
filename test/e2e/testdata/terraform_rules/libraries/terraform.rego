package generic.terraform

import rego.v1

import data.generic.common

# A minimal Terraform rule contract library for the unknown gate tests: it only looks
# the engine's answers up in input._dd.

_dd := object.get(input, "_dd", {})

_placeholder := object.get(_dd, "placeholder", "\u0000dd-unknown")

blocks(type) := object.get(_dd, ["blocks", "resource", type], [])

by_id(id) := object.get(_dd, ["by_id", id], _placeholder)

# A list of a block kind that a rule uses with a common library helper, so the
# gate must compile this library together with the common one.
_nested(block) := object.get(object.get(_dd, "nested", {}), object.get(block._dd_meta, "id", ""), {})

nested(block, name) := list if {
	list := object.get(_nested(block), name, null)
	common.is_list(list)
} else := list if {
	list := block[name]
	common.is_list(list)
} else := [_placeholder] if {
	block[name] == _placeholder
} else := []

related(block, type, path) := [by_id(id) | some id in object.get(_dd, ["related", block._dd_meta.id, type, path], [])]

targets(block, path) := [by_id(id) | some id in object.get(_dd, ["targets", block._dd_meta.id, path], [])]

literal_keys := {"aws_s3_bucket_versioning": {"bucket": {"aws_s3_bucket": ["bucket"]}}}
