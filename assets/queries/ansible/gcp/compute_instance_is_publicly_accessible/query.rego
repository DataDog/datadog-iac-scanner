package Cx

import data.generic.ansible as ansLib

canonical := "gcp_compute_instance"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	compute_instance := task[variant]
	ansLib.checkState(compute_instance)

	compute_instance.network_interfaces[_].access_configs

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(compute_instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.network_interfaces.access_configs", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_compute_instance.network_interfaces.access_configs should not be defined",
		"keyActualValue": "gcp_compute_instance.network_interfaces.access_configs is defined",
	}
}
