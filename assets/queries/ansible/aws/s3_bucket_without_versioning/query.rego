package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "s3_bucket"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	bucket := task[variant]
	ansLib.checkState(bucket)

	not common_lib.valid_key(bucket, "versioning")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(bucket, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "s3_bucket should have versioning set to true",
		"keyActualValue": "s3_bucket does not have versioning (defaults to false)",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	bucket := task[variant]
	ansLib.checkState(bucket)

	not ansLib.isAnsibleTrue(bucket.versioning)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(bucket, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.versioning", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "s3_bucket should have versioning set to true",
		"keyActualValue": "s3_bucket does has versioning set to false",
	}
}
