package Cx

import data.generic.ansible as ansLib

canonical := "lambda"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	lambda := task[variant]
	ansLib.checkState(lambda)

	regex.match(`^[A-Za-z0-9/+=]{40}$`, lambda.aws_access_key)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(lambda, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.aws_access_key", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "lambda.aws_access_key should not be in plaintext",
		"keyActualValue": "lambda.aws_access_key is in plaintext",
	}
}
