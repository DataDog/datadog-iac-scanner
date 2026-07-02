package datadog

import rego.v1

import data.generic.k8s as k8sLib

types := {"initContainers", "containers"}

DatadogPolicy contains result if {
	document := input.document[i]
	metadata := document.metadata

	specInfo := k8sLib.getSpecInfo(document)
	container := specInfo.spec[types[x]][_]

	container.securityContext.privileged == true

	result := {
		"documentId": document.id,
		"resourceType": document.kind,
		"resourceName": metadata.name,
		"searchKey": sprintf("metadata.name={{%s}}.%s.%s.name={{%s}}.securityContext.privileged", [metadata.name, specInfo.path, types[x], container.name]),
	}
}
