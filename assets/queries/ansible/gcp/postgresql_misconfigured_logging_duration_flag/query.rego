package Cx

import data.generic.ansible as ansLib

canonical := "gcp_sql_instance"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)

	ansLib.check_database_flags_content(instance.settings.database_flags, "log_min_duration_statement", -1)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.settings.database_flags", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_sql_instance.settings.database_flags should set the log_min_duration_statement to -1",
		"keyActualValue": "gcp_sql_instance.settings.database_flags doesn't set the log_min_duration_statement to -1",
	}
}
