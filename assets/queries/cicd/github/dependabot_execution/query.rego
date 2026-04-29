package Cx

import data.generic.common as common_lib
import data.generic.cicd as cicd_lib

# Check for insecure-external-code-execution set to 'allow'
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"

	# Iterate through each update configuration
	update := doc.updates[idx]

	# Check if insecure-external-code-execution is explicitly set to allow
	update["insecure-external-code-execution"] == "allow"

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("updates[%d].insecure-external-code-execution={{%s}}", [idx, "allow"]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "insecure-external-code-execution should be set to 'deny' or omitted (defaults to deny)",
		"keyActualValue": "insecure-external-code-execution is set to 'allow', enabling external code execution",
		"searchLine": common_lib.build_search_line(["updates", idx, "insecure-external-code-execution"], []),
		"resourceType": "dependabot_update",
		"resourceName": sprintf("update-%d", [idx])
	}
}
