package Cx

import data.generic.ansible as ans_lib
import data.generic.common as common_lib

canonical := "ec2_group"

CxPolicy[result] {
	task := ans_lib.tasks[id][t]
	variant := ans_lib.get_variants(canonical)[_]
	ec2_instance := task[variant]
	ans_lib.checkState(ec2_instance)

	rule := ec2_instance.rules[idx]

	cidrs := {"cidr_ip": "0.0.0.0/0", "cidr_ipv6": "::/0"}

	cidrValue := cidrs[cidr]

	rule[cidr] == cidrValue

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ans_lib.get_resource_name(ec2_instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.rules.%s", [task.name, variant, cidr]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'ec2_group.rules.%s' should not be %s", [cidr, cidrValue]),
		"keyActualValue": sprintf("'ec2_group.rules.%s' is %s", [cidr, rule[cidr]]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "rules", idx, cidr], []),
	}
}
