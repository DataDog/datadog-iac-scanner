package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "azure_rm_rediscachefirewallrule"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)

	occupied_hosts := common_lib.calc_IP_value(instance.start_ip_address)
	all_hosts := common_lib.calc_IP_value(instance.end_ip_address)
	available := abs(all_hosts - occupied_hosts)

	available > 255

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.start_ip_address", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "azure_rm_rediscachefirewallrule.start_ip_address and end_ip_address should allow up to 255 hosts",
		"keyActualValue": sprintf("azure_rm_rediscachefirewallrule.start_ip_address and end_ip_address allow %d hosts", [available]),
	}
}
