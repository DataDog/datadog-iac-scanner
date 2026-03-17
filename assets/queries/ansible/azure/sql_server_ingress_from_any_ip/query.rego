package Cx

import data.generic.ansible as ansLib

canonical := "azure_rm_sqlfirewallrule"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	fwRule := task[variant]
	ansLib.checkState(fwRule)

	fwRule.start_ip_address == "0.0.0.0"
	isUnsafeEndIpAddress(fwRule.end_ip_address)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(fwRule, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.end_ip_address", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "azure_rm_sqlfirewallrule should allow all IPs",
		"keyActualValue": "azure_rm_sqlfirewallrule should not allow all IPs (range from start_ip_address to end_ip_address)",
	}
}

isUnsafeEndIpAddress("255.255.255.255") = true
