package Cx

import data.generic.ansible as ans_lib
import data.generic.common as common_lib

canonical := "sqs_queue"

CxPolicy[result] {
	task := ans_lib.tasks[id][t]
	variant := ans_lib.get_variants(canonical)[_]
	sqsPolicy := task[variant]
	ans_lib.checkState(sqsPolicy)

	st := common_lib.get_statement(common_lib.get_policy(sqsPolicy.policy))
	statement := st[_]

	common_lib.is_allow_effect(statement)
	common_lib.equalsOrInArray(statement.Action, "*")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ans_lib.get_resource_name(sqsPolicy, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.policy", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "sqs_queue.policy.Statement should not contain Action equal to '*'",
		"keyActualValue": "sqs_queue.policy.Statement contains Action equal to '*'",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "policy"], []),
	}
}
