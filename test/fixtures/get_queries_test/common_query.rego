package datadog

import rego.v1

DatadogPolicy contains result if {
	input.document[i]

	result := {
		"documentId": input.document[i].id,
		"searchKey": "",
	}
}
