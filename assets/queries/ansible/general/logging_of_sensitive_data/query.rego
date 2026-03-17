package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "user"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	action := task[variant]
	ansLib.checkState(action)

	not common_lib.valid_key(task, "no_log")
	common_lib.valid_key(action, "password")

	result := {
		"documentId": id,
		"resourceName": ansLib.get_resource_name(action, canonical, task),
		"resourceType": canonical,
		"searchKey": sprintf("name={{%s}}", [task.name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "'no_log' should be defined and set to 'true' in order to not expose sensitive data",
		"keyActualValue": "'no_log' is not defined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	action := task[variant]
	ansLib.checkState(action)

	task.no_log == false
	common_lib.valid_key(action, "password")

	result := {
		"documentId": id,
		"resourceName": ansLib.get_resource_name(action, canonical, task),
		"resourceType": canonical,
		"searchKey": sprintf("name={{%s}}.no_log", [task.name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'no_log' should be set to 'true' in order to not expose sensitive data",
		"keyActualValue": "'no_log' is set to false",
	}
}
