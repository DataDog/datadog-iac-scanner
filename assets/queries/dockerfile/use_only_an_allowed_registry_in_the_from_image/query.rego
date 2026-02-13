package Cx
import data.generic.common as common_lib

CxPolicy[result] {
	resource := input.document[i].command[name][_]
	resource.Cmd == "from"

	image := resource.Value[0]

	# Check if image contains a registry (has a slash before the image name)
	contains(image, "/")

	# Extract registry from image (everything before first slash)
	imageParts := split(image, "/")
	registry := imageParts[0]

	# Default allowed registries
	allowedRegistries := ["docker.io"]

	# Check if registry is not in allowed list
	not common_lib.inArray(allowedRegistries, registry)

	# Exclude stage references (e.g., "FROM builder1 AS builder2")
	not contains(resource.Value[0], " ")

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("FROM={{%s}}.{{%s}}", [name, resource.Original]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("FROM should use an allowed registry (docker.io), not '%s'", [registry]),
		"keyActualValue": sprintf("FROM is using untrusted registry '%s'", [registry]),
		"resourceName": "dockerfile_container",
		"resourceType": "dockerfile_container",
	}
}
