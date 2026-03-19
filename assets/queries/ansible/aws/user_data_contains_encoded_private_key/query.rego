package Cx

import data.generic.ansible as ansLib

# ec2_lc is variant of autoscaling_launch_config
canonical := "autoscaling_launch_config"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	ec2_lc := task[variant]
	ansLib.checkState(ec2_lc)

	contains(ec2_lc.user_data, "LS0tLS1CR")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ec2_lc, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.user_data", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "ec2_lc.user_data should not contain RSA Private Key",
		"keyActualValue": "ec2_lc.user_data contains RSA Private Key",
	}
}
