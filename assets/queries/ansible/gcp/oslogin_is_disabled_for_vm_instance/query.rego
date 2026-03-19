package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "gcp_compute_instance"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	metadata := instance.metadata
	ansLib.checkState(instance)

	common_lib.valid_key(metadata, "enable-oslogin")

	not ansLib.isAnsibleTrue(metadata["enable-oslogin"])

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.metadata.enable-oslogin", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_compute_instance.metadata.enable-oslogin should be true",
		"keyActualValue": "gcp_compute_instance.metadata.enable-oslogin is false",
	}
}
