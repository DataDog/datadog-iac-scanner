package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

# ec2_lc is variant of autoscaling_launch_config
canonical := "autoscaling_launch_config"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	ec2_lc := task[variant]
	ansLib.checkState(ec2_lc)

	not common_lib.valid_key(ec2_lc, "volumes")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ec2_lc, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "ec2_lc.volumes should be set",
		"keyActualValue": "ec2_lc.volumes is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	ec2_lc := task[variant]
	ansLib.checkState(ec2_lc)

	volume := ec2_lc.volumes[j]
	not common_lib.valid_key(volume, "encrypted")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ec2_lc, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.volumes", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("ec2_lc.volumes[%d].encrypted should be set", [j]),
		"keyActualValue": sprintf("ec2_lc.volumes[%d].encrypted is undefined", [j]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	ec2_lc := task[variant]
	ansLib.checkState(ec2_lc)

	volume := ec2_lc.volumes[j]
	not common_lib.valid_key(volume, "ephemeral")
	ansLib.isAnsibleFalse(ec2_lc.volumes[j].encrypted)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ec2_lc, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.volumes", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("ec2_lc.volumes[%d].encrypted should be set to true or yes", [j]),
		"keyActualValue": sprintf("ec2_lc.volumes[%d].encrypted is not set to true or yes", [j]),
	}
}
