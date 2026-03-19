package Cx

import data.generic.ansible as ansLib

canonical := "ec2_group"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	ec2_group := task[variant]
	ansLib.checkState(ec2_group)

	rule := ec2_group.rules[index]
	rule.cidr_ip == "0.0.0.0/0"
	rule.proto == "tcp"
	ansLib.isPortInRule(rule, 2383)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ec2_group, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.rules", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("ec2_group.rules[%d] shouldn't open the SQL analysis services port (2383)", [index]),
		"keyActualValue": sprintf("ec2_group.rules[%d] opens the SQL analysis services port (2383)", [index]),
	}
}
