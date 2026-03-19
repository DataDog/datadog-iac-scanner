package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "api_gateway"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	tracing := task[variant]
	ansLib.checkState(tracing)

	not common_lib.valid_key(tracing, "tracing_enabled")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(tracing, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "aws_api_gateway.tracing_enabled should be defined",
		"keyActualValue": "aws_api_gateway.tracing_enabled is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	tracing := task[variant]
	ansLib.checkState(tracing)

	not ansLib.isAnsibleTrue(tracing.tracing_enabled)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(tracing, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.tracing_enabled", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "aws_api_gateway.tracing_enabled should be true",
		"keyActualValue": "aws_api_gateway.tracing_enabled is false",
	}
}
