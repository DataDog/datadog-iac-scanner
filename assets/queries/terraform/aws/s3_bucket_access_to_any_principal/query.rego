package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

pl := {"aws_s3_bucket_policy", "aws_s3_bucket"}

CxPolicy[result] {
	resourceType := pl[r]
	resource := input.document[i].resource[resourceType][name]

	policy := common_lib.json_unmarshal(resource.policy)
	st := common_lib.get_statement(policy)
	statement := st[idx]

	common_lib.is_allow_effect(statement)
	tf_lib.anyPrincipal(statement)

	result := {
		"documentId": input.document[i].id,
		"resourceType": resourceType,
		"resourceName": tf_lib.get_specific_resource_name(resource, "aws_s3_bucket", name),
		"searchKey": sprintf("%s[%s].policy.Statement[%d].Principal", [resourceType, name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s[%s].policy.Principal should not equal to, nor contain '*'", [resourceType, name]),
		"keyActualValue": sprintf("%s[%s].policy.Principal is equal to or contains '*'", [resourceType, name]),
		"searchLine": common_lib.build_search_line(["resource", resourceType, name, "policy", "Statement", idx, "Principal"], []),
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	resourceType := pl[r]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, resourceType, "policy")

	policy := common_lib.json_unmarshal(module[keyToCheck])
	st := common_lib.get_statement(policy)
	statement := st[idx]

	common_lib.is_allow_effect(statement)
	tf_lib.anyPrincipal(statement)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].policy.Statement[%d].Principal", [name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'policy.Principal' should not equal to, nor contain '*'",
		"keyActualValue": "'policy.Principal' is equal to or contains '*'",
		"searchLine": common_lib.build_search_line(["module", name, "policy", "Statement", idx, "Principal"], []),
	}
}
