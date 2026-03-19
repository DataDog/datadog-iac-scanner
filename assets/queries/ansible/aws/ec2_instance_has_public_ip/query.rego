package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

# ec2_launch_template
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	canonical := "ec2_launch_template"
	variant := ansLib.get_variants(canonical)[_]
	ec2_launch_template := task[variant]
	ansLib.checkState(ec2_launch_template)

	ipValue := ec2_launch_template.network_interfaces.associate_public_ip_address
	ansLib.isAnsibleTrue(ipValue)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ec2_launch_template, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.network_interfaces.associate_public_ip_address", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "ec2_launch_template.network_interfaces.associate_public_ip_address should be set to false, 'no' or undefined",
		"keyActualValue": sprintf("ec2_launch_template.network_interfaces.associate_public_ip_address is '%s'", [ipValue]),
	}
}

# ec2_instance
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	canonical := "ec2_instance"
	variant := ansLib.get_variants(canonical)[_]
	ec2_instance := task[variant]
	ansLib.checkState(ec2_instance)

	ipValue := ec2_instance.network.assign_public_ip
	ansLib.isAnsibleTrue(ipValue)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ec2_instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.network.assign_public_ip", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "ec2_instance.network.assign_public_ip should be set to false, 'no' or undefined",
		"keyActualValue": sprintf("ec2_instance.network.assign_public_ip is '%s'", [ipValue]),
	}
}
