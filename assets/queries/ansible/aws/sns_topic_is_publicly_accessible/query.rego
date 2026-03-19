package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "sns_topic"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	snsTopicCommunity := task[variant]
	ansLib.checkState(snsTopicCommunity)
	st := common_lib.get_statement(common_lib.get_policy(snsTopicCommunity.policy))
	statement := st[_]

	statement.Effect == "Allow"
	common_lib.any_principal(statement)
	not common_lib.is_access_limited_to_an_account_id(statement)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(snsTopicCommunity, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.policy", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "sns_topic.policy.Statement shouldn't contain '*' for an AWS Principal",
		"keyActualValue": "sns_topic.policy.Statement contains '*' in an AWS Principal",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "policy"], []),
	}
}
