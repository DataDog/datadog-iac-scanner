package Cx

import data.generic.common as common_lib
import data.generic.cicd as cicd_lib

# Check if workflow is reusable-only (only has workflow_call trigger)
is_reusable_only(doc) {
	string_trigger(doc)
}

is_reusable_only(doc) {
	only_workflow_call(doc)
}

string_trigger(doc) {
	doc.on == "workflow_call"
}

only_workflow_call(doc) {
	count(doc.on) == 1
	doc.on[_] == "workflow_call"
}

only_workflow_call(doc) {
	count(doc.on) == 1
	doc.on[key]
	key == "workflow_call"
}

# Check if concurrency is bare (string only, no cancel-in-progress)
is_bare_concurrency(concurrency) {
	is_string(concurrency)
}

is_bare_concurrency(concurrency) {
	is_object(concurrency)
	concurrency.group
	not object.get(concurrency, "cancel-in-progress", false)
}

# Workflow-level concurrency check
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"

	# Skip reusable-only workflows
	not is_reusable_only(doc)

	# Check workflow has bare concurrency
	concurrency := doc.concurrency
	is_bare_concurrency(concurrency)
	doc_name := object.get(doc, "name", sprintf("document", []))

	result := {
		"documentId": doc.id,
		"searchKey": "concurrency",
		"issueType": "MissingAttribute",
		"keyExpectedValue": "Workflow concurrency should include cancel-in-progress",
		"keyActualValue": "Workflow concurrency is missing cancel-in-progress",
		"searchLine": common_lib.build_search_line(["concurrency"], []),
		"resourceType": "github_action",
		"resourceName": doc_name
	}
}

# Job-level concurrency check when workflow has no concurrency
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"

	# Skip reusable-only workflows
	not is_reusable_only(doc)

	# Workflow has no concurrency
	not doc.concurrency

	# Check job has bare concurrency
	job := doc.jobs[j]
	concurrency := job.concurrency
	is_bare_concurrency(concurrency)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.concurrency", [j]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("Job '%s' concurrency should include cancel-in-progress", [j]),
		"keyActualValue": sprintf("Job '%s' concurrency is missing cancel-in-progress", [j]),
		"searchLine": common_lib.build_search_line(["jobs", j, "concurrency"], []),
		"resourceType": "github_action",
		"resourceName": j
	}
}

# Job-level missing concurrency check when workflow has no concurrency
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"

	# Skip reusable-only workflows
	not is_reusable_only(doc)

	# Workflow has no concurrency
	not doc.concurrency

	# Job has no concurrency
	job := doc.jobs[j]
	not job.concurrency

	# Skip reusable workflow calls (they should be managed by the caller)
	not job.uses

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s", [j]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "Workflow or job should have concurrency limits defined",
		"keyActualValue": "Missing concurrency setting",
		"searchLine": common_lib.build_search_line(["jobs", j], []),
		"resourceType": "github_action",
		"resourceName": j
	}
}
