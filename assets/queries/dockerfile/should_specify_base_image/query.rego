package Cx

CxPolicy[result] {
	resource := input.document[i]

	# Check if there are any FROM commands
	commands := [cmd | cmd := resource.command[_][_]; cmd.Cmd == "from"]
	count(commands) == 0

	result := {
		"documentId": resource.id,
		"searchKey": "Dockerfile",
		"issueType": "MissingAttribute",
		"keyExpectedValue": "Dockerfile should specify a base image with FROM",
		"keyActualValue": "Dockerfile does not contain a FROM instruction",
		"resourceName": "dockerfile_container",
		"resourceType": "dockerfile_container",
	}
}
