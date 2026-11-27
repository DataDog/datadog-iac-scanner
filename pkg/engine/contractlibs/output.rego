package datadog.output

import rego.v1

# Findings-only Contract v2 result constructor, aligned with Datadog CSPM's
# dd_output.format convention. Rules never emit "pass" records, documentId,
# resourceType, resourceName, or searchKey strings; the scanner derives exact
# source ranges, module attribution, remediation points, and stable
# fingerprints from (resource.id, path).

_reserved_keys := {"_dd_id", "path", "documentId", "resourceType", "resourceName", "searchKey", "id", "queryName", "severity", "platform", "category", "descriptionID", "cloudProvider"}

format(resource, details) := object.union_n([
	object.remove(details, _reserved_keys),
	{
		"_dd_id": _resource_id(resource),
		"path": _norm_path(object.get(details, "path", [])),
	},
])

_resource_id(resource) := resource if is_string(resource)

_resource_id(resource) := resource.id if is_string(resource.id)

_norm_path(path) := [path] if {
	is_string(path)
	path != ""
} else := [] if {
	is_string(path)
} else := path if {
	is_array(path)
} else := path
