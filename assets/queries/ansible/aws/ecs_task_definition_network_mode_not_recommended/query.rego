package Cx

import data.generic.ansible as ansLib

canonical := "ecs_taskdefinition"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	ecs_taskdefinition := task[variant]
	ansLib.checkState(ecs_taskdefinition)

	ecs_taskdefinition.network_mode != "awsvpc"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ecs_taskdefinition, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.network_mode", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'ecs_taskdefinition.network_mode' should be set to 'awsvpc'",
		"keyActualValue": sprintf("'ecs_taskdefinition.network_mode' is '%s'", [ecs_taskdefinition.network_mode]),
	}
}
