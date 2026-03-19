package Cx

import data.generic.ansible as ansLib

canonical := "gcp_sql_instance"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	database_flags := instance.settings.database_flags
	ansLib.checkState(instance)

	database_flags[x].name == "log_min_messages"
	not check_database_flags_content(database_flags[x])

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.settings.database_flags.log_min_messages", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_sql_instance.settings.database_flags should set 'log_min_messages' to a valid value",
		"keyActualValue": "gcp_sql_instance.settings.database_flags doesn't set 'log_min_messages' to a valid value",
	}
}

check_database_flags_content(database_flags) {
	cmd := ["fatal", "panic", "log", "error", "warning", "notice", "info", "debug1", "debug2", "debug3", "debug4", "debug5"]
	contains(database_flags.value, cmd[k])
}
