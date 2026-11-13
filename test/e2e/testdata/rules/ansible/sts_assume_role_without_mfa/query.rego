package datadog

import rego.v1

import data.generic.ansible as ansLib
import data.generic.common as common_lib

DatadogPolicy contains result if {
	attributes := {"mfa_serial_number", "mfa_token"}
	some id, t
	task := ansLib.tasks[id][t]
	sts := task["community.aws.sts_assume_role"]
	ansLib.checkState(sts)

	some j in attributes
	not common_lib.valid_key(sts, j)

	result := {
		"documentId": id,
		"resourceType": "sts_assume_role",
		"resourceName": ansLib.resource_name(sts, "sts_assume_role", task),
		"searchKey": sprintf("name={{%s}}.community.aws.sts_assume_role", [task.name]),
	}
}
