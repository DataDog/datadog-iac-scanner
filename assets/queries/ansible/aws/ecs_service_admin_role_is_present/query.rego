package Cx

import data.generic.ansible as ansLib

canonical := "ecs_service"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	ecs := task[variant]
	ansLib.checkState(ecs)

	is_string(ecs.role)
	contains(lower(ecs.role), "admin")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ecs, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.role", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "ecs_service.role should not be an admin role",
		"keyActualValue": "ecs_service.role is an admin role",
	}
}
