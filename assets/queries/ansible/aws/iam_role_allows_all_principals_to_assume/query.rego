package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "iam_managed_policy"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	iamPolicy := task[variant]
	ansLib.checkState(iamPolicy)

	policy := common_lib.get_policy(iamPolicy.policy)
	st := common_lib.get_statement(policy)
	statement := st[_]

	common_lib.is_allow_effect(statement)
	aws := statement.Principal.AWS

	common_lib.allowsAllPrincipalsToAssume(aws, statement)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(iamPolicy, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.policy", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "iam_managed_policy.policy.Statement.Principal.AWS should not contain ':root",
		"keyActualValue": "iam_managed_policy.policy.Statement.Principal.AWS contains ':root'",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "policy"], []),
	}
}
