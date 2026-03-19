package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "s3_bucket"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	bucket := task[variant]
	ansLib.checkState(bucket)

	ansLib.isAnsibleFalse(bucket.debug_botocore_endpoint_logs)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(bucket, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.debug_botocore_endpoint_logs", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "s3_bucket.debug_botocore_endpoint_logs should be true",
		"keyActualValue": "s3_bucket.debug_botocore_endpoint_logs is false",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	bucket := task[variant]
	ansLib.checkState(bucket)

	not common_lib.valid_key(bucket, "debug_botocore_endpoint_logs")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(bucket, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "s3_bucket.debug_botocore_endpoint_logs should be defined",
		"keyActualValue": "s3_bucket.debug_botocore_endpoint_logs is undefined",
	}
}
