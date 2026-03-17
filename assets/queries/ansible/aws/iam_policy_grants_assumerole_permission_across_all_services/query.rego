package Cx

import data.generic.ansible as ans_lib
import data.generic.common as common_lib

canonical := "iam_managed_policy"

CxPolicy[result] {
	task := ans_lib.tasks[id][t]
	variant := ans_lib.get_variants(canonical)[_]
	iamPolicy := task[variant]
	ans_lib.checkState(iamPolicy)

	st := common_lib.get_statement(common_lib.get_policy(iamPolicy.policy))
	statement := st[_]

	common_lib.is_allow_effect(statement)

	common_lib.equalsOrInArray(statement.Principal.AWS, "*")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ans_lib.get_resource_name(iamPolicy, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.policy", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "iam_managed_policy.policy.Statement.Principal.AWS should not contain '*'",
		"keyActualValue": "iam_managed_policy.policy.Statement.Principal.AWS contains '*'",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "policy"], []),
	}
}
