package Cx

import data.generic.ansible as ansLib

canonical := "lambda_policy"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	lambda := task[variant]

	ansLib.checkState(lambda)
	lambda.action != "lambda:InvokeFunction"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(lambda, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.action", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("name={{%s}}.{{%s}}.action should be 'lambda:InvokeFunction'", [task.name, variant]),
		"keyActualValue": sprintf("name={{%s}}.{{%s}}.action is %s", [task.name, variant, lambda.action]),
	}
}
