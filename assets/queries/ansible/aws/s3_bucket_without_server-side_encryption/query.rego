package Cx

import data.generic.ansible as ansLib

canonical := "s3_bucket"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	s3_bucket := task[variant]
	ansLib.checkState(s3_bucket)

	s3_bucket.encryption == "none"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(s3_bucket, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.encryption", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "s3_bucket.encryption should not be 'none'",
		"keyActualValue": "s3_bucket.encryption is 'none'",
	}
}
