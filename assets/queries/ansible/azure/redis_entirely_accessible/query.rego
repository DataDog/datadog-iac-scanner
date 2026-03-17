package Cx

import data.generic.ansible as ansLib

canonical := "azure_rm_rediscachefirewallrule"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	firewall_rule := task[variant]
	ansLib.checkState(firewall_rule)

	firewall_rule.start_ip_address == "0.0.0.0"
	firewall_rule.end_ip_address == "0.0.0.0"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(firewall_rule, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.start_ip_address", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "azure_rm_rediscachefirewallrule start_ip and end_ip should not equal to '0.0.0.0'",
		"keyActualValue": "azure_rm_rediscachefirewallrule start_ip and end_ip are equal to '0.0.0.0'",
	}
}
