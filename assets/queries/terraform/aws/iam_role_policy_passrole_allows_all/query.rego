package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	resource := input.document[i].resource.aws_iam_role_policy[name]
	policy := resource.policy

	out := common_lib.json_unmarshal(policy)
	st := common_lib.get_statement(out)
	statement := st[idx]

	common_lib.is_allow_effect(statement)
	check_passrole(statement)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_iam_role_policy",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_iam_role_policy[%s].policy.Statement[%d].Action", [name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'aws_iam_role_policy.policy.Statement.Action' iam:passrole shouldn't have Resource '*'",
		"keyActualValue": "'aws_iam_role_policy.policy.Statement.Action' iam:passrole has Resource '*'",
		"searchLine": common_lib.build_search_line(["resource", "aws_iam_role_policy", name, "policy", "Statement", idx, "Action"], []),
	}
}

check_passrole(statement) {
	common_lib.equalsOrInArray(statement.Action, "iam:passrole")
	common_lib.equalsOrInArray(statement.Resource, "*")
}
