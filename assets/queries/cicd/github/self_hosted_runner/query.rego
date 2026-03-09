package Cx

import data.generic.common as common_lib

# Check for self-hosted runner in runs-on (string format)
CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j]

	# Check if runs-on is a string and equals self-hosted
	is_string(job["runs-on"])
	job["runs-on"] == "self-hosted"

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.runs-on={{%s}}", [j, job["runs-on"]]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Job should not use self-hosted runners in public repositories",
		"keyActualValue": "Job uses self-hosted runner which may be unsafe in public repositories",
		"searchLine": common_lib.build_search_line(["jobs", j, "runs-on"], []),
		"resourceType": "github_job",
		"resourceName": j
	}
}

# Check for self-hosted runner in runs-on (array format)
CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j]

	# Check if runs-on is an array and first element is self-hosted
	is_array(job["runs-on"])
	count(job["runs-on"]) > 0
	job["runs-on"][0] == "self-hosted"

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.runs-on[0]={{%s}}", [j, job["runs-on"][0]]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Job should not use self-hosted runners in public repositories",
		"keyActualValue": "Job uses self-hosted runner which may be unsafe in public repositories",
		"searchLine": common_lib.build_search_line(["jobs", j, "runs-on"], []),
		"resourceType": "github_job",
		"resourceName": j
	}
}

# Check for potential expression-based self-hosted runner (lower confidence)
CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j]

	# Check if runs-on contains an expression
	is_string(job["runs-on"])
	contains(job["runs-on"], "${{")

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.runs-on={{%s}}", [j, job["runs-on"]]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Job should not use potentially self-hosted runners in public repositories",
		"keyActualValue": "Job uses expression for runs-on which might expand to self-hosted runner",
		"searchLine": common_lib.build_search_line(["jobs", j, "runs-on"], []),
		"resourceType": "github_job",
		"resourceName": j
	}
}

# Check for expression in array format
CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j]

	# Check if runs-on is an array with expression
	is_array(job["runs-on"])
	count(job["runs-on"]) > 0
	runner := job["runs-on"][0]
	is_string(runner)
	contains(runner, "${{")

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.runs-on[0]={{%s}}", [j, runner]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Job should not use potentially self-hosted runners in public repositories",
		"keyActualValue": "Job uses expression for runs-on which might expand to self-hosted runner",
		"searchLine": common_lib.build_search_line(["jobs", j, "runs-on"], []),
		"resourceType": "github_job",
		"resourceName": j
	}
}
