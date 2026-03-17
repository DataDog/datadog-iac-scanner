package Cx

import data.generic.ansible as ansLib

canonical := "gcp_sql_instance"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)

	contains(instance.database_version, "MYSQL")
	ansLib.check_database_flags_content(instance.settings.database_flags, "local_infile", "off")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.settings.database_flags", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "cloud_gcp_sql_instance.settings.database_flags should be correct",
		"keyActualValue": "cloud_gcp_sql_instance.settings.database_flags.name is 'local_infile' and cloud_gcp_sql_instance.settings.database_flags.value is not 'off'",
	}
}
