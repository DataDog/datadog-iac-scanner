package datadog.terraform

import rego.v1

import data.datadog.iac

# Terraform-specific Contract v2 helpers (isolated from platform-agnostic iac.*).

_root_res(res) := r if {
	is_object(res)
	r := object.get(res, "_dd_root", null)
	is_object(r)
} else := res

# Returns the resolved provider resource block for res, or undefined when none.
provider_config(res) := cfg if {
	pid := object.get(_root_res(res), ["platform", "terraform", "provider_id"], "")
	pid != ""
	cfg := object.get(input, ["by_id", pid], null)
	cfg != null
}

# True when two resources resolve to the same Terraform provider configuration.
# Missing IDs compare as the same ambient provider, matching Terraform's default
# provider scope. Nested block views are compared through their root resources.
same_provider_config(a, b) if {
	provider_a := object.get(_root_res(a), ["platform", "terraform", "provider_id"], "")
	provider_b := object.get(_root_res(b), ["platform", "terraform", "provider_id"], "")
	provider_a == provider_b
}

# Reads a plan-computed attribute (absent in HCL configuration, present in
# terraform plan -json planned_values). Undefined for unknown values.
computed(res, path) := v if {
	comp := object.get(_root_res(res), ["platform", "terraform", "computed"], {})
	p := _norm_path(path)
	v := object.get(comp, p, null)
	v != null
	not iac.is_unknown(computed_view(res), path)
}

# Stateful view of provider-computed Plan values, for rules that explicitly
# inspect runtime settings omitted from configuration (including dynamic blocks).
# Unknown computed values remain unknown; paths still refer to the real resource.
computed_view(res) := object.union(_computed_object(root, prefix), {
	"_dd_parent_state": object.get(root, ["platform", "terraform", "computed_state"], {}),
	"_dd_prefix": prefix,
	"_dd_root": root,
}) if {
	root := _root_res(res)
	source_kind(root) == "plan"
	prefix := object.get(res, "_dd_prefix", [])
}

_computed_object(root, prefix) := value if {
	computed := object.get(root, ["platform", "terraform", "computed"], {})
	value := object.get(computed, prefix, {})
	is_object(value)
} else := {}

# Select a view for one value path: configured fields remain authoritative,
# including unknowns; known unset Plan fields may use provider-computed values.
# Read the same relative path from the returned view and bind findings to the
# original resource. This also supports stateful nested block views.
value_view(res, path) := computed_view(res) if {
	source_kind(res) == "plan"
	iac.is_unset(res, path)
} else := res

# True when the source configuration explicitly used a null expression. Plan
# values may still contain a known provider default at that path, so this proof
# is separate from the runtime null state. Nested views keep their original
# resource-relative path.
source_is_null(res, path) if {
	root := _root_res(res)
	source_kind(root) == "plan"
	source_null := object.get(root, ["platform", "terraform", "source_null"], {})
	source_null[iac.path_key(iac.path_of(res, path))] == true
}

source_is_null(res, path) if {
	source_kind(res) != "plan"
	iac.is_null_value(res, path)
}

# Returns the parsed CloudWatch metric filter AST when available.
filter_expr(res) := expr if {
	expr := object.get(_root_res(res), ["derived", "filter_expr", "pattern"], null)
	expr != null
}

filter_pattern_known(res) if {
	_ := filter_expr(res)
}

source_kind(res) := object.get(_root_res(res), ["platform", "terraform", "source_kind"], "hcl")

_norm_path(path) := [path] if is_string(path)

_norm_path(path) := path if is_array(path)
