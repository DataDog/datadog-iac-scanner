package Cx

CxPolicy[result] {
	resource := input.document[i].command[name][_]
	resource.Cmd == "add"

	flags := resource.Flags
	contains(flags[j], "chmod")
	contains(flags[j], "777")

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("FROM={{%s}}.{{%s}}", [name, resource.Original]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "ADD instruction should not use --chmod=777",
		"keyActualValue": "ADD instruction uses --chmod=777, making files world-writable",
		"resourceName": "dockerfile_container",
		"resourceType": "dockerfile_container",
	}
}

CxPolicy[result] {
	resource := input.document[i].command[name][_]
	resource.Cmd == "copy"

	flags := resource.Flags
	contains(flags[j], "chmod")
	contains(flags[j], "777")

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("FROM={{%s}}.{{%s}}", [name, resource.Original]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "COPY instruction should not use --chmod=777",
		"keyActualValue": "COPY instruction uses --chmod=777, making files world-writable",
		"resourceName": "dockerfile_container",
		"resourceType": "dockerfile_container",
	}
}
