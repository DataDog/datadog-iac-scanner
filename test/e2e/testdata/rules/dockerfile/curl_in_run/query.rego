package datadog

import rego.v1

DatadogPolicy contains result if {
	some i, stage, idx
	instruction := input.document[i].command[stage][idx]
	instruction.Cmd == "run"
	some value in instruction.Value
	contains(value, "curl http")

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("FROM={{%s}}.{{%s}}", [stage, instruction.Original]),
		"resourceName": "dockerfile_container",
		"resourceType": "dockerfile_container",
	}
}
