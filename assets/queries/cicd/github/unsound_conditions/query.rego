package Cx

import data.generic.cicd as cicd_lib
import data.generic.common as common_lib

# Detect potentially unsound job-level conditions
CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j]

	# Check if job has parsed expressions in the if condition
	check_unsound_condition(job)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.if", [j]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Condition with fenced expression should not have trailing whitespace",
		"keyActualValue": "Condition may always evaluate to true due to YAML block scalar style with trailing newlines",
		"searchLine": common_lib.build_search_line(["jobs", j, "if"], []),
		"resourceType": "github_job",
		"resourceName": j
	}
}

# Detect potentially unsound step-level conditions
CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j]
	step := job.steps[s]

	# Check if step has parsed expressions in the if condition
	check_unsound_condition(step)

	# Get step name if available
	step_name := object.get(step, "name", sprintf("step-%d", [s]))

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.steps[%d].if", [j, s]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Condition with fenced expression should not have trailing whitespace",
		"keyActualValue": sprintf("Step '%s' condition may always evaluate to true due to YAML block scalar style", [step_name]),
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", s, "if"], []),
		"resourceType": "github_step",
		"resourceName": step_name
	}
}

# Composite GitHub Action: detect potentially unsound step-level conditions.
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.is_composite_action(doc)

	step := doc.runs.steps[s]

	check_unsound_condition(step)

	step_name := object.get(step, "name", sprintf("step-%d", [s]))

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("runs.steps[%d].if", [s]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Condition with fenced expression should not have trailing whitespace",
		"keyActualValue": sprintf("Step '%s' condition may always evaluate to true due to YAML block scalar style", [step_name]),
		"searchLine": common_lib.build_search_line(["runs", "steps", s, "if"], []),
		"resourceType": "github_step",
		"resourceName": step_name
	}
}

check_unsound_condition(job_or_step) {
	# Get parsed expressions for the if condition
	parsed_exprs := job_or_step._parsed_expressions_if[_]
	parsed_exprs.parse_ok == true
	# Get the raw if condition
	condition := job_or_step["if"]
	#
	trimmed := trim_space(condition)
	startswith(trimmed, "${{")
	endswith(trimmed, "}}")
	condition != trimmed
}
