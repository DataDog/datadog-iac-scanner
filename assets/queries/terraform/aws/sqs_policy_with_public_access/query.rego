package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	resource := input.document[i].resource.aws_sqs_queue_policy[name]

	policy := common_lib.json_unmarshal(resource.policy)
	st := common_lib.get_statement(policy)
	statement := st[idx]

	common_lib.is_allow_effect(statement)
	sub_path := tf_lib.wildcard_principal_sub_path(statement)

	principal_path := concat(".", array.concat(["Principal"], sub_path))

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_sqs_queue_policy",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_sqs_queue_policy[%s].policy.Statement[%d].%s", [name, idx, principal_path]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'policy.Statement.%s' should not equal '*'", [principal_path]),
		"keyActualValue": sprintf("'policy.Statement.%s' is equal '*'", [principal_path]),
		"searchLine": common_lib.build_search_line(
			array.concat(["resource", "aws_sqs_queue_policy", name, "policy", "Statement", idx, "Principal"], sub_path),
			[],
		),
	}
}

#######################################################################################################

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_sqs_queue_policy", "policy")

	policy := common_lib.json_unmarshal(module[keyToCheck])
	st := common_lib.get_statement(policy)
	statement := st[idx]

	common_lib.is_allow_effect(statement)
	sub_path := tf_lib.wildcard_principal_sub_path(statement)

	principal_path := concat(".", array.concat(["Principal"], sub_path))

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s.Statement[%d].%s", [name, keyToCheck, idx, principal_path]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'module[%s].%s.Statement.%s' should not equal '*'", [name, keyToCheck, principal_path]),
		"keyActualValue": sprintf("'module[%s].%s.Statement.%s' is equal '*'", [name, keyToCheck, principal_path]),
		"searchLine": common_lib.build_search_line(
			array.concat(["module", name, keyToCheck, "Statement", idx, "Principal"], sub_path),
			[],
		),
	}
}
