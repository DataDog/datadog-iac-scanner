package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "codebuild_project"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	aws_codebuild := task[variant]
	ansLib.checkState(aws_codebuild)

	not common_lib.valid_key(aws_codebuild, "encryption_key")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(aws_codebuild, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "aws_codebuild.encryption_key should be set",
		"keyActualValue": "aws_codebuild.encryption_key is undefined",
	}
}
