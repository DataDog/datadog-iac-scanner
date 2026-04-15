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
		"resourceType": "github_action",
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
		"resourceType": "github_action",
		"resourceName": j
	}
}

# Check for potential expression-based self-hosted runner
CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j]

	check_self_hosted(job)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.runs-on={{%s}}", [j, job["runs-on"]]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Job should not use potentially self-hosted runners in public repositories",
		"keyActualValue": "Job uses expression for runs-on which might expand to self-hosted runner",
		"searchLine": common_lib.build_search_line(["jobs", j, "runs-on"], []),
		"resourceType": "github_action",
		"resourceName": j
	}
}

# Check for runner group (implies self-hosted runner)
CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j]

	# Check if runs-on is an object with 'group' key
	is_object(job["runs-on"])
	job["runs-on"].group

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.runs-on.group={{%s}}", [j, job["runs-on"].group]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Job should not use self-hosted runners in public repositories",
		"keyActualValue": "Job uses runner group which implies self-hosted runner",
		"searchLine": common_lib.build_search_line(["jobs", j, "runs-on"], []),
		"resourceType": "github_action",
		"resourceName": j
	}
}

# Helper function to check if job has self-hosted in matrix
has_self_hosted_in_matrix(job) {
	job.strategy
	job.strategy.matrix
	matrix_value := job.strategy.matrix[_]
	is_string(matrix_value)
	contains(matrix_value, "self-hosted")
} else {
	job.strategy
	job.strategy.matrix
	matrix_value := job.strategy.matrix[_]
	is_array(matrix_value)
	matrix_value[_] == "self-hosted"
}

# Case 1: Expression references matrix and matrix contains self-hosted
check_self_hosted(job) {
	# Get parsed expressions
	parsed_exprs := job._parsed_expressions_runs_on[_]
	parsed_exprs.parse_ok == true

	# Check if expression references matrix
	contains(parsed_exprs.raw, "matrix.")

	# Look for self-hosted in strategy.matrix values
	has_self_hosted_in_matrix(job)
}

# Case 2: Expression doesn't reference matrix
check_self_hosted(job) {
	# Get parsed expressions
	parsed_exprs := job._parsed_expressions_runs_on[_]
	parsed_exprs.parse_ok == true

	# Expression exists but doesn't reference matrix
	not contains(parsed_exprs.raw, "matrix.")
}
