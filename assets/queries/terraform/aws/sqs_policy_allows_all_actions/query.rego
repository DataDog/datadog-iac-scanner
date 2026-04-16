package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	resource := input.document[i].resource.aws_sqs_queue_policy[name]

	policy := common_lib.json_unmarshal(resource.policy)
	st := common_lib.get_statement(policy)
	statement := st[idx]
	statement.Effect == "Allow"
	tf_lib.anyPrincipal(statement)
	common_lib.containsOrInArrayContains(statement.Action, "*")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_sqs_queue_policy",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_sqs_queue_policy[%s].policy.Statement[%d].Action", [name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'policy.Statement.Action' should not equal '*'",
		"keyActualValue": "'policy.Statement.Action' is equal '*'",
		"searchLine": common_lib.build_search_line(["resource", "aws_sqs_queue_policy", name, "policy", "Statement", idx, "Action"], []),
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_sqs_queue_policy", "policy")

	policy := common_lib.json_unmarshal(module[keyToCheck])
	st := common_lib.get_statement(policy)
	statement := st[idx]
	statement.Effect == "Allow"
	tf_lib.anyPrincipal(statement)
	common_lib.containsOrInArrayContains(statement.Action, "*")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s.Statement[%d].Action", [name, keyToCheck, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'policy.Statement.Action' should not equal '*'",
		"keyActualValue": "'policy.Statement.Action' is equal '*'",
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck, "Statement", idx, "Action"], []),
	}
}
