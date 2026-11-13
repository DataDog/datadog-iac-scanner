package datadog

import rego.v1

import data.generic.k8s as k8sLib

DatadogPolicy contains result if {
	document := input.document[i]
	specInfo := k8sLib.spec_info(document)
	container := specInfo.spec.containers[_]

	not container.securityContext.seccompProfile

	result := {
		"documentId": document.id,
		"resourceType": document.kind,
		"resourceName": document.metadata.name,
		"searchKey": sprintf("metadata.name={{%s}}.%s.containers.name={{%s}}.securityContext.seccompProfile", [document.metadata.name, specInfo.path, container.name]),
	}
}
