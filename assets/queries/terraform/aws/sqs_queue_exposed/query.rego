package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	resource := input.document[i].resource.aws_sqs_queue[name]

	policy := common_lib.json_unmarshal(resource.policy)
	st := common_lib.get_statement(policy)
	statement := st[idx]

	common_lib.is_allow_effect(statement)
	tf_lib.anyPrincipal(statement)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_sqs_queue",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_sqs_queue[%s].policy.Statement[%d].Principal", [name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("resource.aws_sqs_queue[%s].policy.Principal shouldn't get the queue publicly accessible", [name]),
		"keyActualValue": sprintf("resource.aws_sqs_queue[%s].policy.Principal does get the queue publicly accessible", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_sqs_queue", name, "policy", "Statement", idx, "Principal"], []),
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_sqs_queue", "policy")

	policy := common_lib.json_unmarshal(module[keyToCheck])
	st := common_lib.get_statement(policy)
	statement := st[idx]

	common_lib.is_allow_effect(statement)
	tf_lib.anyPrincipal(statement)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s.Statement[%d].Principal", [name, keyToCheck, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'policy.Principal' shouldn't get the queue publicly accessible",
		"keyActualValue": "'policy.Principal' does get the queue publicly accessible",
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck, "Statement", idx, "Principal"], []),
	}
}
