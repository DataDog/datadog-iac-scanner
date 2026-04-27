package Cx

import data.generic.common as common_lib
import data.generic.cicd as cicd_lib

CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"

	cicd_lib.has_dangerous_trigger(doc)
	doc_name := object.get(doc, "name", "document")

	result := {
		"documentId": doc.id,
		"searchKey": "on",
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Workflow should not use pull_request_target or workflow_run triggers",
		"keyActualValue": "Workflow uses dangerous trigger which is almost always used insecurely",
		"searchLine": common_lib.build_search_line(["on"], []),
		"resourceType": "github_action",
		"resourceName": doc_name
	}
}
