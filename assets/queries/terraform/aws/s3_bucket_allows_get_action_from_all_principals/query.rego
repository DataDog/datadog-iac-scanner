package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	pl := {"aws_s3_bucket_policy", "aws_s3_bucket"}
	resource := input.document[i].resource[pl[r]][name]

	policy := common_lib.json_unmarshal(resource.policy)
	st := common_lib.get_statement(policy)
	statement := st[idx]
	statement.Effect == "Allow"
	tf_lib.anyPrincipal(statement)
	common_lib.containsOrInArrayContains(statement.Action, "get")

	result := {
		"documentId": input.document[i].id,
		"resourceType": pl[r],
		"resourceName": tf_lib.get_specific_resource_name(resource, "aws_s3_bucket", name),
		"searchKey": sprintf("%s[%s].policy.Statement[%d].Action", [pl[r], name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s[%s].policy.Action should not be a 'Get' action", [pl[r], name]),
		"keyActualValue": sprintf("%s[%s].policy.Action is a 'Get' action", [pl[r], name]),
		"searchLine": common_lib.build_search_line(["resource", pl[r], name, "policy", "Statement", idx, "Action"], []),
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_s3_bucket", "policy")

	policy := common_lib.json_unmarshal(module[keyToCheck])
	st := common_lib.get_statement(policy)
	statement := st[idx]
	statement.Effect == "Allow"
	tf_lib.anyPrincipal(statement)
	common_lib.containsOrInArrayContains(statement.Action, "get")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].%s.Statement[%d].Action", [name, keyToCheck, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("module[%s].policy.Action should not be a 'Get' action", [name]),
		"keyActualValue": sprintf("module[%s].policy.Action is a 'Get' action", [name]),
		"searchLine": common_lib.build_search_line(["module", name, keyToCheck, "Statement", idx, "Action"], []),
	}
}
