package datadog

import rego.v1

DatadogPolicy contains result if {
	document := input.document[i]
	document.kind == "Deployment"
	not has_network_policy
	result := {
		"documentId": document.id,
		"resourceType": document.kind,
		"resourceName": document.metadata.name,
		"searchKey": sprintf("metadata.name={{%s}}", [document.metadata.name]),
	}
}

has_network_policy if {
	input.document[_].kind == "NetworkPolicy"
}
