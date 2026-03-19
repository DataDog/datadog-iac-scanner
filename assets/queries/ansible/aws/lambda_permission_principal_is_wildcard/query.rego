package Cx

import data.generic.ansible as ansLib

canonical := "lambda_policy"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	lambda := task[variant]
	ansLib.checkState(lambda)

	contains(lambda.principal, "*")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(lambda, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.principal", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("name={{%s}}.{{%s}}.principal shouldn't contain a wildcard", [task.name, variant]),
		"keyActualValue": sprintf("name={{%s}}.{{%s}}.principal contains a wildcard", [task.name, variant]),
	}
}
