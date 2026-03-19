package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

canonical := "azure_rm_rediscachefirewallrule"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	firewall_rule := task[variant]
	ansLib.checkState(firewall_rule)

	not commonLib.isPrivateIP(firewall_rule.start_ip_address)
	not commonLib.isPrivateIP(firewall_rule.end_ip_address)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(firewall_rule, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.start_ip_address", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "azure_rm_rediscachefirewallrule ip range should be private",
		"keyActualValue": "azure_rm_rediscachefirewallrule ip range is public",
	}
}
