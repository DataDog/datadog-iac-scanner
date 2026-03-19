package Cx

import data.generic.common as common_lib
import data.generic.ansible as ansLib

canonical := "gcp_compute_firewall"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)

	common_lib.is_ingress(instance)
	common_lib.is_unrestricted(instance.source_ranges[_])
	allowed := instance.allowed
	ansLib.allowsPort(allowed[k], "22")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.allowed.ip_protocol=%s.ports", [task.name, variant, allowed[k].ip_protocol]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("gcp_compute_firewall.allowed.ip_protocol=%s.ports shouldn't contain SSH port (22) with unrestricted ingress traffic", [allowed[k].ip_protocol]),
		"keyActualValue": sprintf("gcp_compute_firewall.allowed.ip_protocol=%s.ports contain SSH port (22) with unrestricted ingress traffic", [allowed[k].ip_protocol]),
	}
}
