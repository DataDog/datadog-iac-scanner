package Cx

import data.generic.ansible as ansLib

canonical := "s3_object"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	aws_s3 := task[variant]
	ansLib.checkState(aws_s3)

	contains(aws_s3.permission, "public")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(aws_s3, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.permission", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "aws_s3.permission shouldn't allow public access",
		"keyActualValue": "aws_s3.permission allows public access",
	}
}
