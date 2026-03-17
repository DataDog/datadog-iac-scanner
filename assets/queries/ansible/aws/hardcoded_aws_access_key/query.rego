package Cx

import data.generic.ansible as ansLib

canonical := "ec2_instance"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	ec2_instance := task[variant]
	ansLib.checkState(ec2_instance)

	re_match("([^A-Z0-9])[A-Z0-9]{20}([^A-Z0-9])", ec2_instance.user_data)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ec2_instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.user_data", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'ec2_instance.user_data' shouldn't contain access key",
		"keyActualValue": "'ec2_instance.user_data' contains access key",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	ec2_instance := task[variant]
	ansLib.checkState(ec2_instance)

	re_match("[A-Za-z0-9/+=]{40}([^A-Za-z0-9/+=])", ec2_instance.user_data)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ec2_instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.user_data", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'ec2_instance.user_data' shouldn't contain access key",
		"keyActualValue": "'ec2_instance.user_data' contains access key",
	}
}
