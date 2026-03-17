package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "iam_role"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	iamRole := task[variant]
	ansLib.checkState(iamRole)

	policy := iamRole.assume_role_policy_document
	st := common_lib.get_statement(common_lib.get_policy(policy))
	statement := st[_]

	common_lib.is_allow_effect(statement)
	common_lib.is_cross_account(statement)
	common_lib.is_assume_role(statement)

	not common_lib.has_external_id(statement)
	not common_lib.has_mfa(statement)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(iamRole, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.assume_role_policy_document", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "assume_role_policy_document should not contain ':root",
		"keyActualValue": "assume_role_policy_document contains ':root'",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "assume_role_policy_document"], []),
	}
}
