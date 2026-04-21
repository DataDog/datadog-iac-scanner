package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	resource := input.document[i].resource.aws_iam_role[name]

	re_match("Service", resource.assume_role_policy)
	policy := common_lib.json_unmarshal(resource.assume_role_policy)
	st := common_lib.get_statement(policy)
	statement := st[idx]

	common_lib.is_allow_effect(statement)
	sub_path := tf_lib.wildcard_principal_sub_path(statement)

	principal_path := concat(".", array.concat(["Principal"], sub_path))

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_iam_role",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_iam_role[%s].assume_role_policy.Statement[%d].%s", [name, idx, principal_path]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'assume_role_policy.Statement.%s' shouldn't contain '*'", [principal_path]),
		"keyActualValue": sprintf("'assume_role_policy.Statement.%s' contains '*'", [principal_path]),
		"searchLine": common_lib.build_search_line(
			array.concat(["resource", "aws_iam_role", name, "assume_role_policy", "Statement", idx, "Principal"], sub_path),
			[],
		),
	}
}
