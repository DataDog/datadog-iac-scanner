package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "cloudwatchlogs_log_group"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	logGroup := task[variant]
	ansLib.checkState(logGroup)

	not common_lib.valid_key(logGroup, "log_group_name")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(logGroup, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "cloudwatchlogs_log_grouptracing_enabled should contain log_group_name",
		"keyActualValue": "cloudwatchlogs_log_group does not contain log_group_name defined",
	}
}
