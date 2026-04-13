package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	resource := input.document[i].resource.aws_sqs_queue_policy[name]

	policy := common_lib.json_unmarshal(resource.policy)
	st := common_lib.get_statement(policy)
	statement := st[idx]

	common_lib.is_allow_effect(statement)
	check_principal(statement.Principal, "*")
	tf_lib.anyPrincipal(statement)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_sqs_queue_policy",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_sqs_queue_policy[%s].policy.Statement[%d].Principal", [name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'policy.Statement.Principal.AWS' should not equal '*'",
		"keyActualValue": "'policy.Statement.Principal.AWS' is equal '*'",
		"searchLine": common_lib.build_search_line(["resource", "aws_sqs_queue_policy", name, "policy", "Statement", idx, "Principal"], []),
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
	check_principal(statement.Principal, "*")
	tf_lib.anyPrincipal(statement)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s.Statement[%d].Principal", [name, keyToCheck, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'module[%s].%s.Statement.Principal.AWS' should not equal '*'", [name, keyToCheck]),
		"keyActualValue": sprintf("'module[%s].%s.Statement.Principal.AWS' is equal '*'", [name, keyToCheck]),
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck, "Statement", idx, "Principal"], []),
	}
}

check_principal(field, value) {
	is_object(field)
	some i
	val := [x | x := field[i]; common_lib.containsOrInArrayContains(x, value)]
	count(val) > 0
} else {
	common_lib.containsOrInArrayContains(field, "*")
}
