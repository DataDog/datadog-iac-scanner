package datadog

import rego.v1

import data.generic.ansible as ansLib
import data.generic.common as common_lib

modules := {"community.aws.aws_api_gateway", "aws_api_gateway"}

DatadogPolicy contains result if {
	task := ansLib.tasks[id][t]
	api_gateway := task[modules[m]]
	ansLib.checkState(api_gateway)

	not common_lib.valid_key(api_gateway, "validate_certs")

	result := {
		"documentId": id,
		"resourceType": modules[m],
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, modules[m]]),
	}
}

DatadogPolicy contains result if {
	task := ansLib.tasks[id][t]
	api_gateway := task[modules[m]]
	ansLib.checkState(api_gateway)

	not ansLib.isAnsibleTrue(api_gateway.validate_certs)

	result := {
		"documentId": id,
		"resourceType": modules[m],
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.validate_certs", [task.name, modules[m]]),
	}
}
