package Cx

import data.generic.ansible as ansLib

canonical := "azure_rm_postgresqlconfiguration"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	pgConfig := task[variant]
	ansLib.checkState(pgConfig)

	is_string(pgConfig.name)
	is_string(pgConfig.value)

	lower(pgConfig.name) == "log_duration"
	upper(pgConfig.value) != "ON"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(pgConfig, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.value", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "azure_rm_postgresqlconfiguration.value should be 'ON' for 'log_duration'",
		"keyActualValue": "azure_rm_postgresqlconfiguration.value is 'OFF' for 'log_duration'",
	}
}
