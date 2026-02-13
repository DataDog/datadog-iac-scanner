package Cx

CxPolicy[result] {
	resource := input.document[i].command[name][_]
	resource.Cmd == "run"

	splitValue = split(resource.Value[j], " ")

	links := [link | link := splitValue[_]
			contains(link, "http:")
			not contains(link, "https:")

			# Exclude localhost URLs
			not contains(link, "http://localhost")
			not contains(link, "http://127.0.0.1")
			not contains(link, "http://[::1]")
	]

	count(links) > 0

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("FROM={{%s}}.{{%s}}", [name, resource.Original]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Use https:// instead of http://",
		"keyActualValue": sprintf("Using http:// in '%s'", [links[0]]),
		"resourceName": "dockerfile_container",
		"resourceType": "dockerfile_container",
	}
}
