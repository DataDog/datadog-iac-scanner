package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "ec2_ami"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	ec2Ami := task[variant]
	ansLib.checkState(ec2Ami)

	not common_lib.valid_key(ec2Ami.device_mapping, "encrypted")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ec2Ami, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "ec2_ami.device_mapping.device_name.encrypted should be set to true",
		"keyActualValue": "ec2_ami.device_mapping.device_name.encrypted is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	ec2Ami := task[variant]
	ansLib.checkState(ec2Ami)

	not ansLib.isAnsibleTrue(ec2Ami.device_mapping.encrypted)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ec2Ami, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.device_mapping.encrypted", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "ec2_ami.device_mapping.encrypted should be set to true",
		"keyActualValue": "ec2_ami.device_mapping.encrypted is set to false",
	}
}
