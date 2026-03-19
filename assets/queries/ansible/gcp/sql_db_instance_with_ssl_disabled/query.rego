package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "gcp_sql_instance"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	sql_instance := task[variant]
	ansLib.checkState(sql_instance)

	path := getPathDefinitions(sql_instance)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(sql_instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}%s", [task.name, variant, path.defined]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("gcp_sql_instance.%s should be defined", [path.undefined]),
		"keyActualValue": sprintf("gcp_sql_instance.%s is undefined", [path.undefined]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	sql_instance := task[variant]
	ansLib.checkState(sql_instance)

	not ansLib.isAnsibleTrue(sql_instance.settings.ip_configuration.require_ssl)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(sql_instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.settings.ip_configuration.require_ssl", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_sql_instance.settings.ip_configuration.require_ssl should be true",
		"keyActualValue": "gcp_sql_instance.settings.ip_configuration.require_ssl is false",
	}
}

getPathDefinitions(instance) = result {
	not common_lib.valid_key(instance, "settings")
	result = {"defined": "", "undefined": "settings"}
}

getPathDefinitions(instance) = result {
	not common_lib.valid_key(instance.settings, "ip_configuration")
	result = {"defined": ".settings", "undefined": "settings.ip_configuration"}
}

getPathDefinitions(instance) = result {
	not common_lib.valid_key(instance.settings.ip_configuration, "require_ssl")
	result = {"defined": ".settings.ip_configuration", "undefined": "settings.ip_configuration.require_ssl"}
}
