package Cx

import data.generic.ansible as ansLib

canonical := "cloudtrail"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cloudtrail := task[variant]
	ansLib.checkState(cloudtrail)

	ansLib.isAnsibleFalse(cloudtrail.enable_logging)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudtrail, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.enable_logging", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "cloudtrail.enable_logging should be true",
		"keyActualValue": "cloudtrail.enable_logging is false",
	}
}
