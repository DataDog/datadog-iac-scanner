package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "efs"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	efs := task[variant]

	ansLib.checkState(efs)
	not common_lib.valid_key(efs, "tags")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(efs, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("name={{%s}}.{{%s}}.tags should be set", [task.name, variant]),
		"keyActualValue": sprintf("name={{%s}}.{{%s}}.tags is not defined", [task.name, variant]),
	}
}
