package Cx

import data.generic.ansible as ansLib

canonical := "ec2_ami"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	ec2Ami := task[variant]
	ansLib.checkState(ec2Ami)

	amiIsShared(ec2Ami.launch_permissions)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ec2Ami, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.launch_permissions", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "ec2_ami.launch_permissions just allows one user to launch the AMI",
		"keyActualValue": "ec2_ami.launch_permissions allows more than one user to launch the AMI",
	}
}

amiIsShared(attribute) = allow {
	attribute.group_names
	allow = true
}

amiIsShared(attribute) = allow {
	count(attribute.user_ids) > 1
	allow = true
}
