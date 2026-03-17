package Cx

import data.generic.ansible as ansLib

canonical := "gcp_compute_instance"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)

	ansLib.isAnsibleTrue(instance.can_ip_forward)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.can_ip_forward", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_compute_instance.can_ip_forward should be set to false",
		"keyActualValue": "gcp_compute_instance.can_ip_forward is true",
	}
}
