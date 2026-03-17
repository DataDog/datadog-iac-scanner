package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "kms_key"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	kms := task[variant]
	ansLib.checkState(kms)

	kms.enabled == true
	not common_lib.valid_key(kms, "pending_window")
	not common_lib.valid_key(kms, "enable_key_rotation")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(kms, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "community.aws.aws_kms.enable_key_rotation should be set",
		"keyActualValue": "community.aws.aws_kms.enable_key_rotation is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	kms := task[variant]
	ansLib.checkState(kms)

	kms.enabled == true
	not common_lib.valid_key(kms, "pending_window")
	kms.enable_key_rotation == false

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(kms, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.enable_key_rotation", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "community.aws.aws_kms.enable_key_rotation should be set to true",
		"keyActualValue": "community.aws.aws_kms.enable_key_rotation is set to false",
	}
}
