package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "sqs_queue"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	sqs_queue := task[variant]
	ansLib.checkState(sqs_queue)

	st := common_lib.get_statement(common_lib.get_policy(sqs_queue.policy))
	statement := st[_]

	common_lib.is_allow_effect(statement)
	statement.Principal == "*"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(sqs_queue, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.policy", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "sqs_queue.policy.Principal shouldn't get the queue publicly accessible",
		"keyActualValue": "sqs_queue.policy.Principal does get the queue publicly accessible",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "policy"], []),
	}
}
