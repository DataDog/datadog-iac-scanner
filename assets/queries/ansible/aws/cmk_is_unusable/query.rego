package Cx

import data.generic.ansible as ansLib

canonical := "kms_key"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	kms := task[variant]
	ansLib.checkState(kms)

	kms.enabled == false

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(kms, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.enabled", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "community.aws.aws_kms.enabled should be set to true",
		"keyActualValue": "community.aws.aws_kms.enabled is set to false",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	kms := task[variant]
	ansLib.checkState(kms)

	kms.pending_window

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(kms, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.pending_window", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "community.aws.aws_kms.pending_window should be undefined",
		"keyActualValue": "community.aws.aws_kms.pending_window is set",
	}
}
