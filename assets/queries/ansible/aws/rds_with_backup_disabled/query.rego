package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "rds_instance"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)

	instance.backup_retention_period == 0

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.backup_retention_period", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "rds_instance should have the property 'backup_retention_period' greater than 0",
		"keyActualValue": "rds_instance has the property 'backup_retention_period' assigned to 0",
	}
}
