package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "api_gateway"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	api_gateway := task[variant]
	ansLib.checkState(api_gateway)

	not common_lib.valid_key(api_gateway, "validate_certs")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(api_gateway, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "aws_api_gateway.validate_certs should be set",
		"keyActualValue": "aws_api_gateway.validate_certs is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	api_gateway := task[variant]
	ansLib.checkState(api_gateway)

	not ansLib.isAnsibleTrue(api_gateway.validate_certs)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(api_gateway, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.validate_certs", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "aws_api_gateway.validate_certs should be set to yes",
		"keyActualValue": "aws_api_gateway.validate_certs is not set to yes",
	}
}
