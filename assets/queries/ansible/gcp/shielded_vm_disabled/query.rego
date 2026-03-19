package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "gcp_compute_instance"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)

	not common_lib.valid_key(instance, "shielded_instance_config")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "gcp_compute_instance.shielded_instance_config should be defined",
		"keyActualValue": "gcp_compute_instance.shielded_instance_config is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)
	attributes := ["enable_integrity_monitoring", "enable_secure_boot", "enable_vtpm"]
	attr := attributes[j]

	not common_lib.valid_key(instance.shielded_instance_config, attr)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.shielded_instance_config", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("gcp_compute_instance.shielded_instance_config.%s should be defined", [attributes[j]]),
		"keyActualValue": sprintf("gcp_compute_instance.shielded_instance_config.%s is undefined", [attributes[j]]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)
	attributes := ["enable_integrity_monitoring", "enable_secure_boot", "enable_vtpm"]

	ansLib.isAnsibleFalse(instance.shielded_instance_config[attributes[j]])

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.shielded_instance_config.%s", [task.name, variant, attributes[j]]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("gcp_compute_instance.shielded_instance_config.%s should be true", [attributes[j]]),
		"keyActualValue": sprintf("gcp_compute_instance.shielded_instance_config.%s is false", [attributes[j]]),
	}
}
