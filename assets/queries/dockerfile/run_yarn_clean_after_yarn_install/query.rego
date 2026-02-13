package Cx

CxPolicy[result] {
	resourceFrom := input.document[i].command[name]
	resource := resourceFrom[j]
	resource.Cmd == "run"

	command := concat(" ", resource.Value)

	# Check if command contains yarn install
	contains(command, "yarn install")

	# Check if any other command contains yarn cache clean
	allCommandsWithClean := {x | x := concat(" ", resourceFrom[k].Value); contains(x, "yarn cache clean") }
	count(allCommandsWithClean) == 0

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("FROM={{%s}}.{{%s}}", [name, resource.Original]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'yarn cache clean' should be called after 'yarn install'",
		"keyActualValue": "'yarn install' is not followed by 'yarn cache clean'",
		"resourceName": "dockerfile_container",
		"resourceType": "dockerfile_container",
	}
}
