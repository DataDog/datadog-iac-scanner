package Cx

import data.generic.ansible as ansLib

canonical := "s3_object"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	s3 := task[variant]
	ansLib.checkState(s3)

	s3.permission == "authenticated-read"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(s3, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.permission", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "s3_object should not have read access for all authenticated users",
		"keyActualValue": "s3_object has read access for all authenticated users",
	}
}
