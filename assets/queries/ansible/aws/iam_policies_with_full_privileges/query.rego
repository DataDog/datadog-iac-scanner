package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "iam_managed_policy"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	iamPolicy := task[variant]
	ansLib.checkState(iamPolicy)

	st := common_lib.get_statement(common_lib.get_policy(iamPolicy.policy))
	statement := st[_]

	common_lib.is_allow_effect(statement)
	common_lib.equalsOrInArray(statement.Resource, "*")
	common_lib.equalsOrInArray(statement.Action, "*")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(iamPolicy, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.policy", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "iam_managed_policy.policy.Statement.Action should not contain '*'",
		"keyActualValue": "iam_managed_policy.policy.Statement.Action contains '*'",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "policy"], []),
	}
}
