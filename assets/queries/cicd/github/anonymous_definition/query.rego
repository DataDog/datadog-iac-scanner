package Cx

import data.generic.common as common_lib

# Check for workflow without a name
CxPolicy[result] {
	doc := input.document[i]
	doc.jobs
	not object.get(doc, "name", false)

	result := {
		"documentId": doc.id,
		"searchKey": "on",
		"issueType": "MissingAttribute",
		"keyExpectedValue": "Workflow should have a name defined",
		"keyActualValue": "Workflow does not have a name defined",
		"searchLine": common_lib.build_search_line(["name"], []),
		"resourceType": "github_action",
		"resourceName": "anonymous_workflow"
	}
}

# Check for jobs without names
CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j]

	not object.get(job, "name", false)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s", [j]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("Job '%s' should have a name defined", [j]),
		"keyActualValue": sprintf("Job '%s' does not have a name defined", [j]),
		"searchLine": common_lib.build_search_line(["jobs", j, "name"], []),
		"resourceType": "github_action",
		"resourceName": j
	}
}
