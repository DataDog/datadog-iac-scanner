package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "rds_instance"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)

	not common_lib.valid_key(instance, "storage_encrypted")
	not common_lib.valid_key(instance, "kms_key_id")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "rds_instance.storage_encrypted should be set to true",
		"keyActualValue": "rds_instance.storage_encrypted is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	instance := task[variant]
	ansLib.checkState(instance)

	not ansLib.isAnsibleTrue(instance.storage_encrypted)
	not common_lib.valid_key(instance, "kms_key_id")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.storage_encrypted", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "rds_instance.storage_encrypted should be set to true",
		"keyActualValue": "rds_instance.storage_encrypted is set to false",
	}
}
