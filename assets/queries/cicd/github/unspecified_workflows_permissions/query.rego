package Cx

import data.generic.common as common_lib

CxPolicy[result] {
	doc := input.document[i]
	doc.jobs

	# Check if permissions is missing at workflow level
	not object.get(doc, "permissions", false)

	# Count jobs without permissions
	allJobsLackPermissions(doc.jobs)

	result := {
		"documentId": doc.id,
		"searchKey": "name",
		"issueType": "MissingAttribute",
		"keyExpectedValue": "Explicit permissions should be set for the GITHUB_TOKEN at the workflow level",
		"keyActualValue": "No explicit permissions set for the GITHUB_TOKEN at the workflow level",
		"searchLine": common_lib.build_search_line(["name"], []),
		"resourceType": "github_workflow",
		"resourceName": doc.name
	}
}

CxPolicy[result] {
	doc := input.document[i]
	jobs := doc.jobs

	# Workflow level does not have permissions
	not object.get(doc, "permissions", false)

	# Check individual jobs without permissions
	job := jobs[j]
	not object.get(job, "permissions", false)

	# At least one other job has permissions (mixed state)
	some k
	k != j
	object.get(jobs[k], "permissions", false)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s", [j]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("Job '%s' should have explicit permissions set for the GITHUB_TOKEN", [j]),
		"keyActualValue": sprintf("Job '%s' has no explicit permissions set for the GITHUB_TOKEN", [j]),
		"searchLine": common_lib.build_search_line(["jobs", j], []),
		"resourceType": "github_job",
		"resourceName": j
	}
}

# Helper to check if all jobs lack permissions
allJobsLackPermissions(jobs) {
	count([job | job := jobs[_]; object.get(job, "permissions", false)]) == 0
}
