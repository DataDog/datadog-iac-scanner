package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "ec2_group"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	ec2_group := task[variant]
	ansLib.checkState(ec2_group)
	cidr_fields := ["cidr_ip", "cidr_ipv6"]
	rule := ec2_group.rules[index]

	rule.from_port == 0
	rule.to_port == 0

	not isValidProto(rule.proto)
	ansLib.isEntireNetwork(rule[cidr_fields[_]])

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ec2_group, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.rules", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("ec2_group.rules[%d] should be restricted", [index]),
		"keyActualValue": sprintf("ec2_group.rules[%d] is not restricted", [index]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "rules", index], []),
	}
}

isValidProto(proto) {
	is_string(proto)
	protos = {"tcp", "udp", "icmp", "icmpv6"}
	proto == protos[j]
}

isValidProto(proto) {
	is_number(proto)
	protos = {1, 6, 17, 58}
	proto == protos[j]
}
