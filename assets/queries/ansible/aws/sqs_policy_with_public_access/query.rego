package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "sqs_queue"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	sqsPolicy := task[variant]
	ansLib.checkState(sqsPolicy)

	st := common_lib.get_statement(common_lib.get_policy(sqsPolicy.policy))
	statement := st[_]

	common_lib.is_allow_effect(statement)
	all_principals(statement)
	common_lib.containsOrInArrayContains(statement.Action, "*")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(sqsPolicy, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.policy", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "sqs_queue.policy.Principal should not equal to '*'",
		"keyActualValue": "sqs_queue.policy.Principal is equal to '*'",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "policy"], []),
	}
}

all_principals(statement) {
	common_lib.containsOrInArrayContains(statement.Principal.AWS, "*")
} else {
	statement.Principal == "*"
}
