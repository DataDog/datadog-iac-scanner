package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "gcp_storage_bucket"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	storage_bucket := task[variant]
	ansLib.checkState(storage_bucket)

	not common_lib.valid_key(storage_bucket, "versioning")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(storage_bucket, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "gcp_storage_bucket.versioning should be defined",
		"keyActualValue": "gcp_storage_bucket.versioning is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	storage_bucket := task[variant]
	ansLib.checkState(storage_bucket)

	not ansLib.isAnsibleTrue(storage_bucket.versioning.enabled)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(storage_bucket, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.versioning.enabled", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_storage_bucket.versioning.enabled should be true",
		"keyActualValue": "gcp_storage_bucket.versioning.enabled is false",
	}
}
