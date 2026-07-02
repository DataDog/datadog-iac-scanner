package datadog

import rego.v1

DatadogPolicy contains result if {
	resource := input.document[i].resource
	resource == "<VALUE>"

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("%s", [resource]),
	}
}
