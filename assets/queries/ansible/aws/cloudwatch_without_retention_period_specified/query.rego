package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "cloudwatchlogs_log_group"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cloudwatchlogs_log_group := task[variant]
	ansLib.checkState(cloudwatchlogs_log_group)

	not common_lib.valid_key(cloudwatchlogs_log_group, "retention")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudwatchlogs_log_group, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "cloudwatchlogs_log_group.retention should be set",
		"keyActualValue": "cloudwatchlogs_log_group.retention is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cloudwatchlogs_log_group := task[variant]
	ansLib.checkState(cloudwatchlogs_log_group)
	value := cloudwatchlogs_log_group.retention

	validValues = [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653]

	not common_lib.inArray(validValues, value)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudwatchlogs_log_group, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.retention", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "cloudwatchlogs_log_group.retention should be set and valid",
		"keyActualValue": "cloudwatchlogs_log_group.retention is set and invalid",
	}
}
