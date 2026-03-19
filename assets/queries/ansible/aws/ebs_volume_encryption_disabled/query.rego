package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "ec2_vol"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	ec2_vol := task[variant]
	ansLib.checkState(ec2_vol)
	object.get(ec2_vol, "state", "present") != "list"

	ansLib.isAnsibleFalse(ec2_vol.encrypted)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ec2_vol, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.encrypted", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "ec2_vol.encrypted should be enabled",
		"keyActualValue": "ec2_vol.encrypted is disabled",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	ec2_vol := task[variant]
	ansLib.checkState(ec2_vol)
	object.get(ec2_vol, "state", "present") != "list"

	not common_lib.valid_key(ec2_vol, "encrypted")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ec2_vol, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "ec2_vol.encrypted should be defined",
		"keyActualValue": "ec2_vol.encrypted is undefined",
	}
}
