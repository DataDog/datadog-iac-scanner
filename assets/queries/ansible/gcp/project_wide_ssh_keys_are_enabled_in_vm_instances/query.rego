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

	common_lib.valid_key(metadata, "block-project-ssh-keys")
	not ansLib.isAnsibleTrue(metadata["block-project-ssh-keys"])

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.metadata.block-project-ssh-keys", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_compute_instance.metadata.block-project-ssh-keys should be true",
		"keyActualValue": "gcp_compute_instance.metadata.block-project-ssh-keys is false",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)

	not common_lib.valid_key(instance.metadata, "block-project-ssh-keys")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.metadata", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "gcp_compute_instance.metadata.block-project-ssh-keys should be set to true",
		"keyActualValue": "gcp_compute_instance.metadata.block-project-ssh-keys is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)

	not common_lib.valid_key(instance, "metadata")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "gcp_compute_instance.metadata should be set",
		"keyActualValue": "gcp_compute_instance.metadata is undefined",
	}
}
