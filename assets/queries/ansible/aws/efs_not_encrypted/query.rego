package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "efs"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	efs := task[variant]
	ansLib.checkState(efs)

	not common_lib.valid_key(efs, "encrypt")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(efs, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "efs.encrypt should be set to true",
		"keyActualValue": "efs.encrypt is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	efs := task[variant]
	ansLib.checkState(efs)

	not ansLib.isAnsibleTrue(efs.encrypt)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(efs, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.encrypt", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "efs.encrypt should be set to true",
		"keyActualValue": "efs.encrypt is set to false",
	}
}
