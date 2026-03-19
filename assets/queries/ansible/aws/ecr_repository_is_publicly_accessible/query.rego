package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "ecs_ecr"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cloudwatchlogs := task[variant]
	ansLib.checkState(cloudwatchlogs)

	st := common_lib.get_statement(common_lib.get_policy(cloudwatchlogs.policy))
	statement := st[_]

	common_lib.is_allow_effect(statement)
	contains(statement.Principal, "*")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudwatchlogs, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.policy", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "ecs_ecr.policy.Principal should not equal to '*'",
		"keyActualValue": "ecs_ecr.policy.Principal is equal to '*'",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "policy"], []),
	}
}
