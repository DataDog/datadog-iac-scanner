package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "ecs_service"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	ecs_service := task[variant]
	ansLib.checkState(ecs_service)

	not common_lib.valid_key(ecs_service, "deployment_configuration")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ecs_service, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("%s.deployment_configuration should be defined", [variant]),
		"keyActualValue": sprintf("%s.deployment_configuration is undefined", [variant]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	ecs_service := task[variant]
	ansLib.checkState(ecs_service)

	not checkContent(ecs_service.deployment_configuration)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ecs_service, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.deployment_configuration", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s.deployment_configuration should have at least 1 task running", [variant]),
		"keyActualValue": sprintf("%s.deployment_configuration must have at least 1 task running", [variant]),
	}
}

checkContent(deploymentConfiguration) {
	common_lib.valid_key(deploymentConfiguration, "maximum_percent")
}
checkContent(deploymentConfiguration) {
	common_lib.valid_key(deploymentConfiguration, "minimum_healthy_percent")
}
