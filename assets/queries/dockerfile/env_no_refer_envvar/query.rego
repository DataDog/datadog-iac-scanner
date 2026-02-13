package Cx

CxPolicy[result] {
	resource := input.document[i].command[name][_]
	resource.Cmd == "env"

	envVars := [var | var := resource.Value[j]; j % 3 == 0]
	envValues := [val | val := resource.Value[j]; j % 3 == 1]


	refName := envVars[k]
	referencePatterns := [sprintf("${%s}", [refName]), sprintf("$%s", [refName])]

	contains(envValues[l], referencePatterns[m])

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("FROM={{%s}}.{{%s}}", [name, resource.Original]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "ENV variables should not reference variables defined in the same instruction",
		"keyActualValue": sprintf("ENV variable '%s' references '%s' defined in the same instruction", [envVars[l], refName]),
		"resourceName": "dockerfile_container",
		"resourceType": "dockerfile_container",
	}
}
