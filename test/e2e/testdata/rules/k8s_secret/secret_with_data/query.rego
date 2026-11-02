package datadog

import rego.v1

# Test-only rule reporting every Secret that carries data, so the scans of
# generated Secrets and the redaction of their values can be asserted.
DatadogPolicy contains result if {
	document := input.document[i]
	document.kind == "Secret"

	result := {
		"documentId": document.id,
		"resourceType": "Secret",
		"resourceName": document.metadata.name,
		"searchKey": sprintf("metadata.name={{%s}}.type", [document.metadata.name]),
	}
}
