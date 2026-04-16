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
	statement.Effect == "Allow"
	tf_lib.anyPrincipal(statement)
	common_lib.containsOrInArrayContains(statement.Action, "list")

	result := {
		"documentId": input.document[i].id,
		"resourceType": resourceType,
		"resourceName": tf_lib.get_specific_resource_name(resource, "aws_s3_bucket", name),
		"searchKey": sprintf("%s[%s].policy.Statement[%d].Action", [resourceType, name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'policy.Statement.Action' should not be a 'List' action when 'policy.Statement.Principal' contains '*'",
		"keyActualValue": "'policy.Statement.Action' is a 'List' action when 'policy.Statement.Principal' contains '*'",
		"searchLine": common_lib.build_search_line(["resource", resourceType, name, "policy", "Statement", idx, "Action"], []),
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]
	resourceValue := pl[r]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, resourceValue, "policy")

	policy := common_lib.json_unmarshal(module[keyToCheck])
	st := common_lib.get_statement(policy)
	statement := st[idx]
	statement.Effect == "Allow"
	tf_lib.anyPrincipal(statement)
	common_lib.containsOrInArrayContains(statement.Action, "list")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": sprintf("%s", [name]),
		"searchKey": sprintf("module[%s].policy.Statement[%d].Action", [name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'policy.Statement.Action' should not be a 'List' action when 'policy.Statement.Principal' contains '*'",
		"keyActualValue": "'policy.Statement.Action' is a 'List' action when 'policy.Statement.Principal' contains '*'",
		"searchLine": common_lib.build_search_line(["module", name, "policy", "Statement", idx, "Action"], []),
	}
}
