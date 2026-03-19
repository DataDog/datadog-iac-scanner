package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "efs"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	efs := task[variant]
	ansLib.checkState(efs)

	not common_lib.valid_key(efs, "kms_key_id")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(efs, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "efs.kms_key_id should be set",
		"keyActualValue": "efs.kms_key_id is undefined",
	}
}
