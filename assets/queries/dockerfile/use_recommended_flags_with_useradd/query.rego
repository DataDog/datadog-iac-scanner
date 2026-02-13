package Cx

CxPolicy[result] {
	resource := input.document[i].command[name][_]
	resource.Cmd == "run"

	command := concat(" ", resource.Value)

	# Check if command contains useradd
	contains(command, "useradd")

	# Check if it does NOT contain -l flag (standalone or combined with other flags)
	missing_flag(command)

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("FROM={{%s}}.{{%s}}", [name, resource.Original]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "useradd should use the -l flag to reduce image size",
		"keyActualValue": "useradd is not using the -l flag",
		"resourceName": "dockerfile_container",
		"resourceType": "dockerfile_container",
	}
}

missing_flag(command) {
	not regex.match(".*[\\s]+-[a-zA-Z]*l[a-zA-Z]*(\\s|$).*", command)
	not contains(command, "--no-log-init")
}
