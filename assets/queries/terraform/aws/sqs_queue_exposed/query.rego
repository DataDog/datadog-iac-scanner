package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	resource := input.document[i].resource.aws_sqs_queue[name]

	entry := exposed_statement_entries(resource.policy)[_]
	idx := entry.idx
	sub_path := entry.sub_path

	principal_path := concat(".", array.concat(["Principal"], sub_path))

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_sqs_queue",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_sqs_queue[%s].policy.Statement[%d].%s", [name, idx, principal_path]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("resource.aws_sqs_queue[%s].policy.%s shouldn't get the queue publicly accessible", [name, principal_path]),
		"keyActualValue": sprintf("resource.aws_sqs_queue[%s].policy.%s does get the queue publicly accessible", [name, principal_path]),
		"searchLine": common_lib.build_search_line(
			array.concat(["resource", "aws_sqs_queue", name, "policy", "Statement", idx, "Principal"], sub_path),
			[],
		),
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_sqs_queue", "policy")

	entry := exposed_statement_entries(module[keyToCheck])[_]
	idx := entry.idx
	sub_path := entry.sub_path

	principal_path := concat(".", array.concat(["Principal"], sub_path))

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s.Statement[%d].%s", [name, keyToCheck, idx, principal_path]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'policy.%s' shouldn't get the queue publicly accessible", [principal_path]),
		"keyActualValue": sprintf("'policy.%s' does get the queue publicly accessible", [principal_path]),
		"searchLine": common_lib.build_search_line(
			array.concat(["module", name, keyToCheck, "Statement", idx, "Principal"], sub_path),
			[],
		),
	}
}

exposed_statement_entries(policyValue) = entries {
	policy := common_lib.json_unmarshal(policyValue)
	st := common_lib.get_statement(policy)
	entries := [{"idx": idx, "sub_path": sub_path} |
		statement := st[idx]
		common_lib.is_allow_effect(statement)
		sub_path := tf_lib.wildcard_principal_sub_path(statement)
	]
	count(entries) > 0
}
