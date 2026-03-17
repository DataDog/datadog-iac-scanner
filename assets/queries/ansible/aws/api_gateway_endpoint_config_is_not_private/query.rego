package Cx

import data.generic.ansible as ansLib

canonical := "api_gateway"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	apiGateway := task[variant]
	ansLib.checkState(apiGateway)

	apiGateway.endpoint_type != "PRIVATE"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(apiGateway, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.endpoint_type", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'aws_api_gateway.endpoint_type' should be set to 'PRIVATE'",
		"keyActualValue": "'aws_api_gateway.endpoint_type' is not 'PRIVATE'",
	}
}
