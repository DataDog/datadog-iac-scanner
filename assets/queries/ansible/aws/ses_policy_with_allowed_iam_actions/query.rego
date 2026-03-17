package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "ses_identity_policy"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	sesPolicy := task[variant]
	ansLib.checkState(sesPolicy)

	st := common_lib.get_statement(common_lib.get_policy(sesPolicy.policy))
	statement := st[_]

	common_lib.is_allow_effect(statement)
	common_lib.containsOrInArrayContains(statement.Action, "*")
	common_lib.any_principal(statement)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(sesPolicy, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.policy", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'policy' should not allow IAM actions to all principals",
		"keyActualValue": "'policy' allows IAM actions to all principals",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "policy"], []),
	}
}
