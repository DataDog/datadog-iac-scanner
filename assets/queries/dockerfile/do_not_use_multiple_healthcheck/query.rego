package Cx

CxPolicy[result] {
	resource := input.document[i].command[name]

	# Count HEALTHCHECK instructions
	healthchecks := [hc | hc := resource[_]; hc.Cmd == "healthcheck"]
	count(healthchecks) > 1

	# Report all but the first HEALTHCHECK
	healthcheck := healthchecks[j]
	j > 0

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("FROM={{%s}}.{{%s}}", [name, healthcheck.Original]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Only one HEALTHCHECK instruction should be present",
		"keyActualValue": "Multiple HEALTHCHECK instructions found",
		"resourceName": "dockerfile_container",
		"resourceType": "dockerfile_container",
	}
}
