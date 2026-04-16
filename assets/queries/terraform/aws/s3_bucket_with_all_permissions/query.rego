package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

resource_type := {"aws_s3_bucket_policy", "aws_s3_bucket"}

CxPolicy[result] {
	res_type := resource_type[_]
	resource := input.document[i].resource[res_type][name]

	policy := common_lib.json_unmarshal(resource.policy)
	st := common_lib.get_statement(policy)
	statement := st[idx]
	common_lib.is_allow_effect(statement)
	common_lib.containsOrInArrayContains(statement.Action, "*")
	common_lib.containsOrInArrayContains(statement.Principal, "*")

	result := {
		"documentId": input.document[i].id,
		"resourceType": res_type,
		"resourceName": tf_lib.get_specific_resource_name(resource, res_type, name),
		"searchKey": sprintf("%s[%s].policy.Statement[%d].Action", [res_type, name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'policy.Statement' should not allow all actions to all principal",
		"keyActualValue": "'policy.Statement' allows all actions to all principal",
		"searchLine": common_lib.build_search_line(["resource", res_type, name, "policy", "Statement", idx, "Action"], []),
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	res_type := resource_type[_]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, res_type, "policy")

	policy := common_lib.json_unmarshal(module[keyToCheck])
	st := common_lib.get_statement(policy)
	statement := st[idx]
	common_lib.is_allow_effect(statement)
	common_lib.containsOrInArrayContains(statement.Action, "*")
	common_lib.containsOrInArrayContains(statement.Principal, "*")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].policy.Statement[%d].Action", [name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'policy.Statement' should not allow all actions to all principal",
		"keyActualValue": "'policy.Statement' allows all actions to all principal",
		"searchLine": common_lib.build_search_line(["module", name, "policy", "Statement", idx, "Action"], []),
	}
}
