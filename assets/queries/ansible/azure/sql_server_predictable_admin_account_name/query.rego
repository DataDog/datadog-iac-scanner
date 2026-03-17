package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "azure_rm_sqlserver"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	server := task[variant]
	ansLib.checkState(server)

	common_lib.emptyOrNull(server.admin_username)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(server, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.admin_username", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "azure_rm_sqlserver.admin_username should not be empty",
		"keyActualValue": "azure_rm_sqlserver.admin_username is empty",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	server := task[variant]
	ansLib.checkState(server)

	is_string(server.admin_username)
	check_predictable(server.admin_username)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(server, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.admin_username", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "azure_rm_sqlserver.admin_username should not be predictable",
		"keyActualValue": "azure_rm_sqlserver.admin_username is predictable",
	}
}

check_predictable(username) {
	predictable_names := {"admin", "administrator", "root", "user", "azure_admin", "azure_administrator", "guest"}
	some i
	lower(username) == predictable_names[i]
}
