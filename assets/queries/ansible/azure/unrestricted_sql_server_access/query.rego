package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "azure_rm_sqlfirewallrule"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	rule := task[variant]
	ansLib.checkState(rule)

	startIP_value := common_lib.calc_IP_value(rule.start_ip_address)
	endIP_value := common_lib.calc_IP_value(rule.end_ip_address)

	abs(endIP_value - startIP_value) >= 256

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(rule, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "The difference between the value of azure_rm_sqlfirewallrule end_ip_address and start_ip_address should be less than 256",
		"keyActualValue": "The difference between the value of azure_rm_sqlfirewallrule end_ip_address and start_ip_address is greater than or equal to 256",
	}
}
