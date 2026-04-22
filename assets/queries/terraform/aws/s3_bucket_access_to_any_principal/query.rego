package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

pl := {"aws_s3_bucket_policy", "aws_s3_bucket"}

CxPolicy[result] {
	resourceType := pl[r]
	resource := input.document[i].resource[resourceType][name]

	entry := access_to_any_principal(resource.policy)[_]
	idx := entry.idx
	sub_path := entry.sub_path

	principal_path := concat(".", array.concat(["Principal"], sub_path))

	result := {
		"documentId": input.document[i].id,
		"resourceType": resourceType,
		"resourceName": tf_lib.get_specific_resource_name(resource, "aws_s3_bucket", name),
		"searchKey": sprintf("%s[%s].policy.Statement[%d].%s", [resourceType, name, idx, principal_path]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s[%s].policy.%s should not equal to, nor contain '*'", [resourceType, name, principal_path]),
		"keyActualValue": sprintf("%s[%s].policy.%s is equal to or contains '*'", [resourceType, name, principal_path]),
		"searchLine": common_lib.build_search_line(
			array.concat(["resource", resourceType, name, "policy", "Statement", idx, "Principal"], sub_path),
			[],
		),
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	resourceType := pl[r]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, resourceType, "policy")

	entry := access_to_any_principal(module[keyToCheck])[_]
	idx := entry.idx
	sub_path := entry.sub_path

	principal_path := concat(".", array.concat(["Principal"], sub_path))

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].policy.Statement[%d].%s", [name, idx, principal_path]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'policy.%s' should not equal to, nor contain '*'", [principal_path]),
		"keyActualValue": sprintf("'policy.%s' is equal to or contains '*'", [principal_path]),
		"searchLine": common_lib.build_search_line(
			array.concat(["module", name, "policy", "Statement", idx, "Principal"], sub_path),
			[],
		),
	}
}

access_to_any_principal(policyValue) = entries {
	policy := common_lib.json_unmarshal(policyValue)
	st := common_lib.get_statement(policy)
	entries := [{"idx": idx, "sub_path": sub_path} |
		statement := st[idx]
		common_lib.is_allow_effect(statement)
		sub_path := tf_lib.wildcard_principal_sub_path(statement)
	]
	count(entries) > 0
}
