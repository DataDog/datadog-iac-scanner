package Cx

import data.generic.ansible as ansLib

canonical := "azure_rm_postgresqlconfiguration"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	postgresql_configuration := task[variant]
	ansLib.checkState(postgresql_configuration)

	is_string(postgresql_configuration.name)
	lower(postgresql_configuration.name) == "log_retention"

	is_string(postgresql_configuration.value)
	lower(postgresql_configuration.value) != "on"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(postgresql_configuration, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.value", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "azure_rm_postgresqlconfiguration.value should equal to 'on'",
		"keyActualValue": "azure_rm_postgresqlconfiguration.value is not equal to 'on'",
	}
}
