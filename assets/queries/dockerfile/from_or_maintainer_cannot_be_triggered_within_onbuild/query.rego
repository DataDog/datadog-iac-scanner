package Cx

CxPolicy[result] {
	resource := input.document[i].command[name][_]
	resource.Cmd == "onbuild"

	# Check if it's FROM, MAINTAINER, or another ONBUILD
	invalidCmds := ["from", "maintainer", "onbuild"]
	resource.SubCmd == invalidCmds[_]

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("FROM={{%s}}.{{%s}}", [name, resource.Original]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "ONBUILD should not trigger FROM, MAINTAINER, or ONBUILD",
		"keyActualValue": sprintf("ONBUILD is triggering %s", [upper(resource.SubCmd)]),
		"resourceName": "dockerfile_container",
		"resourceType": "dockerfile_container",
	}
}
