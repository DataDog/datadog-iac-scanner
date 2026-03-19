package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "ec2_group"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	ec2_group := task[variant]
	ansLib.checkState(ec2_group)
	rule := ec2_group.rules[index]

	unknownPort(rule.from_port, rule.to_port)
	isEntireNetwork(rule)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ec2_group, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.rules", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("ec2_group.rules[%d] port_range should not contain unknown ports and should not be exposed to the entire Internet", [index]),
		"keyActualValue": sprintf("ec2_group.rules[%d] port_range contains unknown ports and are exposed to the entire Internet", [index]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "rules", index, "from_port"], []),
	}
}

unknownPort(from_port, to_port) {
	port := numbers.range(from_port, to_port)[i]
	not common_lib.valid_key(common_lib.tcpPortsMap, port)
}

isEntireNetwork(rule) {
	ansLib.isEntireNetwork(rule.cidr_ip)
}

isEntireNetwork(rule) {
	ansLib.isEntireNetwork(rule.cidr_ipv6)
}
