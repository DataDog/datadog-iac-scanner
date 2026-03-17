package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "lambda"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	lambda := task[variant]
	ansLib.checkState(lambda)

	not common_lib.valid_key(lambda, "tracing_mode")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(lambda, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "lambda.tracing_mode should be set",
		"keyActualValue": "lambda.tracing_mode is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	lambda := task[variant]
	ansLib.checkState(lambda)

	lambda.tracing_mode != "Active"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(lambda, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.tracing_mode", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "lambda.tracing_mode should be set to 'Active'",
		"keyActualValue": "lambda.tracing_mode is not set to 'Active'",
	}
}
