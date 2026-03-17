package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "cloudformation"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cloudformation := task[variant]
	ansLib.checkState(cloudformation)

	not common_lib.valid_key(cloudformation, "notification_arns")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudformation, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "cloudformation.notification_arns should be set",
		"keyActualValue": "cloudformation.notification_arns is undefined",
	}
}
