package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "gcp_storage_bucket"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	storage_bucket := task[variant]
	ansLib.checkState(storage_bucket)

	not common_lib.valid_key(storage_bucket, "logging")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(storage_bucket, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "gcp_storage_bucket.logging should be defined",
		"keyActualValue": "gcp_storage_bucket.logging is undefined",
	}
}
