package Cx

import data.generic.ansible as ansLib

canonical := "rds_instance"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	rds_instance := task[variant]
	ansLib.checkState(rds_instance)

	ansLib.isAnsibleTrue(rds_instance.publicly_accessible)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(rds_instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.publicly_accessible", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s.publicly_accessible should be false", [variant]),
		"keyActualValue": sprintf("%s.publicly_accessible is true", [variant]),
	}
}
