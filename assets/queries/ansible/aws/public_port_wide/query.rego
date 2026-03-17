package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "ec2_group"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	ec2_group := task[variant]
	ansLib.checkState(ec2_group)
	fromPort := ec2_group.rules[index].from_port
	toPort := ec2_group.rules[index].to_port

	toPort - fromPort > 0

	cidr := ec2_group.rules[index].cidr_ip
	ansLib.isEntireNetwork(cidr)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ec2_group, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.rules", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("ec2_group.rules[%d] shouldn't have public port wide", [index]),
		"keyActualValue": sprintf("ec2_group.rules[%d] has public port wide", [index]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "rules", index], []),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	ec2_group := task[variant]
	ansLib.checkState(ec2_group)
	fromPort := ec2_group.rules[index].from_port
	toPort := ec2_group.rules[index].to_port

	toPort - fromPort > 0

	cidr := ec2_group.rules[index].cidr_ipv6
	ansLib.isEntireNetwork(cidr)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ec2_group, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.rules", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("ec2_group.rules[%d] shouldn't have public port wide", [index]),
		"keyActualValue": sprintf("ec2_group.rules[%d] has public port wide", [index]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "rules", index], []),
	}
}
