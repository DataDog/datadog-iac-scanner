package datadog

import rego.v1

DatadogPolicy contains result if {
	some document in input.document
	some name, service in object.get(document, "services", {})
	object.get(service, "privileged", false) == true

	result := {
		"documentId": document.id,
		"searchKey": sprintf("services.{{%s}}.privileged", [name]),
		"resourceName": name,
		"resourceType": "dockercompose_service",
	}
}
