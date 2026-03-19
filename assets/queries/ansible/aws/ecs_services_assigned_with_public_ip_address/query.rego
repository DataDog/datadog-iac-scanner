package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "ecs_service"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	ecs_service := task[variant]
	ansLib.checkState(ecs_service)

	ecs_service.network_configuration.assign_public_ip

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ecs_service, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.network_configuration.assign_public_ip", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s.network_configuration.assign_public_ip' should be set to false (default value is false)", [variant]),
		"keyActualValue": sprintf("'%s.network_configuration.assign_public_ip' is set to true", [variant]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "network_configuration", "assign_public_ip"], []),
	}
}
