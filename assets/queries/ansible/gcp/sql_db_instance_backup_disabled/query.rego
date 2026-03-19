package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "gcp_sql_instance"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)

	path := getPathDefinitions(instance)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}%s", [task.name, variant, path.defined]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("gcp_sql_instance.%s should be defined", [path.undefined]),
		"keyActualValue": sprintf("gcp_sql_instance.%s is undefined", [path.undefined]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)

	not ansLib.isAnsibleTrue(instance.settings.backup_configuration.enabled)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.settings.backup_configuration.enabled", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_sql_instance.settings.backup_configuration.require_ssl should be true",
		"keyActualValue": "gcp_sql_instance.settings.backup_configuration.require_ssl is false",
	}
}

getPathDefinitions(instance) = result {
	not common_lib.valid_key(instance, "settings")
	result = {"defined": "", "undefined": "settings"}
}

getPathDefinitions(instance) = result {
	not common_lib.valid_key(instance.settings, "backup_configuration")
	result = {"defined": ".settings", "undefined": "settings.backup_configuration"}
}

getPathDefinitions(instance) = result {
	not common_lib.valid_key(instance.settings.backup_configuration, "enabled")
	result = {"defined": ".settings.backup_configuration", "undefined": "settings.backup_configuration.enabled"}
}
