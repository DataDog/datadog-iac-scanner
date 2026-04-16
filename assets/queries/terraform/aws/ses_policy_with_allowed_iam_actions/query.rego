package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	resource := input.document[i].resource.aws_ses_identity_policy[name]

	policy := common_lib.json_unmarshal(resource.policy)
	st := common_lib.get_statement(policy)
	statement := st[idx]
	statement.Effect == "Allow"
	tf_lib.anyPrincipal(statement)
	common_lib.containsOrInArrayContains(statement.Action, "*")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_ses_identity_policy",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_ses_identity_policy[%s].policy.Statement[%d].Action", [name, idx]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'policy' should not allow IAM actions to all principals",
		"keyActualValue": "'policy' allows IAM actions to all principals",
		"searchLine": common_lib.build_search_line(["resource", "aws_ses_identity_policy", name, "policy", "Statement", idx, "Action"], []),
	}
}
