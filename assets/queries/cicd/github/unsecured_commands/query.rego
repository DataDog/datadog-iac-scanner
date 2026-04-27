package Cx

import data.generic.cicd as cicd_lib
import data.generic.common as common_lib

CxPolicy[result] {

	env := input.document[i].env["ACTIONS_ALLOW_UNSECURE_COMMANDS"]
	is_true(env)


	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("env.ACTIONS_ALLOW_UNSECURE_COMMANDS={{%s}}", [env]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "ACTIONS_ALLOW_UNSECURE_COMMANDS environment variable is not set as true.",
		"keyActualValue": "ACTIONS_ALLOW_UNSECURE_COMMANDS environment variable is set as true.",
        "searchLine": common_lib.build_search_line(["env", "ACTIONS_ALLOW_UNSECURE_COMMANDS"],[]),
		"resourceType": "github_action",
		"resourceName": get_workflow_name(input.document[i])
	}
}

CxPolicy[result] {

	env := input.document[i].jobs[j].env["ACTIONS_ALLOW_UNSECURE_COMMANDS"]
	is_true(env)


	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("env.ACTIONS_ALLOW_UNSECURE_COMMANDS={{%s}}", [env]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "ACTIONS_ALLOW_UNSECURE_COMMANDS environment variable is not set as true.",
		"keyActualValue": "ACTIONS_ALLOW_UNSECURE_COMMANDS environment variable is set as true.",
        "searchLine": common_lib.build_search_line(["jobs", j, "env", "ACTIONS_ALLOW_UNSECURE_COMMANDS"],[]),
		"resourceType": "github_action",
		"resourceName": get_job_name(input.document[i].jobs[j], j)
	}
}

CxPolicy[result] {

	env := input.document[i].jobs[j].steps[k].env["ACTIONS_ALLOW_UNSECURE_COMMANDS"]
	is_true(env)
	
	
	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("env.ACTIONS_ALLOW_UNSECURE_COMMANDS={{%s}}", [env]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "ACTIONS_ALLOW_UNSECURE_COMMANDS environment variable is not set as true.",
		"keyActualValue": "ACTIONS_ALLOW_UNSECURE_COMMANDS environment variable is set as true.",
        "searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "env", "ACTIONS_ALLOW_UNSECURE_COMMANDS"],[]),
		"resourceType": "github_action",
		"resourceName": get_step_name(input.document[i].jobs[j].steps[k], k)
	}
}

# Composite GitHub Action: ACTIONS_ALLOW_UNSECURE_COMMANDS in a step env block.
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.is_composite_action(doc)

	step := doc.runs.steps[k]
	env := step.env["ACTIONS_ALLOW_UNSECURE_COMMANDS"]
	is_true(env)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("env.ACTIONS_ALLOW_UNSECURE_COMMANDS={{%s}}", [env]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "ACTIONS_ALLOW_UNSECURE_COMMANDS environment variable is not set as true.",
		"keyActualValue": "ACTIONS_ALLOW_UNSECURE_COMMANDS environment variable is set as true.",
		"searchLine": common_lib.build_search_line(["runs", "steps", k, "env", "ACTIONS_ALLOW_UNSECURE_COMMANDS"], []),
		"resourceType": "github_action",
		"resourceName": get_step_name(step, k)
	}
}

is_true(env) {
	env == true
} else {
	lower(env) == "true"
}


get_step_name(step, s) := step_name{
	step_name := step.name
} else := step_name {
	step_name := sprintf("step-%d", [s])
}

get_workflow_name(document) := workflow_name {
	workflow_name := document.name
} else := workflow_name {
	workflow_name := "workflow"
}

get_job_name(job, j) := job_name {
	job_name := job.name
} else := job_name {
	job_name := sprintf("job-%d", [j])
}

