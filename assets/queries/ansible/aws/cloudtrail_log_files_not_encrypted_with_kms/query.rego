package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "cloudtrail"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cloudtrail := task[variant]
	ansLib.checkState(cloudtrail)

	not common_lib.valid_key(cloudtrail, "kms_key_id")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudtrail, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "cloudtrail.kms_key_id should be set",
		"keyActualValue": "cloudtrail.kms_key_id is undefined",
	}
}
