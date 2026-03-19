package Cx

import data.generic.ansible as ansLib

canonical := "ec2_group"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	group := task[variant]
	ansLib.checkState(group)

	searchKey := getCidrBlock(group)

	splitted := regex.split("{{|}}", searchKey)
	errorPath := substring(splitted[0], 0, count(splitted[0]) - 1)
	errorValue := splitted[1]

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(group, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.%s", [task.name, variant, searchKey]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("ec2_group.%s should not contain the value '%s'", [errorPath, errorValue]),
		"keyActualValue": sprintf("ec2_group.%s contains value '%s'", [errorPath, errorValue]),
	}
}

getCidrBlock(sg) = path {
	isUnsafeIp(sg.rules[r].cidr_ip)
	path := "rules.cidr_ip={{0.0.0.0/0}}"
} else = path {
	isUnsafeIp(sg.rules[r].cidr_ip[c])
	path := "rules.cidr_ip.{{0.0.0.0/0}}"
} else = path {
	isUnsafeIp(sg.rules_egress[r].cidr_ip)
	path := "rules_egress.cidr_ip={{0.0.0.0/0}}"
} else = path {
	isUnsafeIp(sg.rules_egress[r].cidr_ip[c])
	path := "rules_egress.cidr_ip.{{0.0.0.0/0}}"
} else = path {
	isUnsafeIpv6(sg.rules[r].cidr_ipv6)
	path := "rules.cidr_ipv6={{::/0}}"
} else = path {
	isUnsafeIpv6(sg.rules[r].cidr_ipv6[c])
	path := "rules.cidr_ipv6.{{::/0}}"
} else = path {
	isUnsafeIpv6(sg.rules_egress[r].cidr_ipv6)
	path := "rules_egress.cidr_ipv6={{::/0}}"
} else = path {
	isUnsafeIpv6(sg.rules_egress[r].cidr_ipv6[c])
	path := "rules_egress.cidr_ipv6.{{::/0}}"
}

isUnsafeIp("0.0.0.0/0") = true

isUnsafeIpv6("::/0") = true
