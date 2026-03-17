package Cx

import data.generic.ansible as ansLib

canonical := "gcp_compute_instance"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)

	ansLib.isAnsibleTrue(instance.metadata["serial-port-enable"])

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.metadata.serial-port-enable", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_compute_instance.metadata.serial-port-enable should be undefined or set to false",
		"keyActualValue": "gcp_compute_instance.metadata.serial-port-enable is set to true",
	}
}
