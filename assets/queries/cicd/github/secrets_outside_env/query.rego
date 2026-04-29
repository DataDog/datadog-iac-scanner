package Cx

import data.generic.common as common_lib
import data.generic.cicd as cicd_lib
import future.keywords.in

# Check for secrets usage in step run blocks outside dedicated environments
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	job := doc.jobs[j]

	# Skip if job has an environment defined (secrets are scoped to environment)
	not job.environment

	# Skip reusable workflow calls (they have 'uses' at job level)
	not job.uses

	# Check step run blocks for secret references
	step := job.steps[s]
	parsed_exprs := step._parsed_expressions_run[_]

	# Verify parsing succeeded
	parsed_exprs.parse_ok == true

	# Check if the expression references secrets (excluding GITHUB_TOKEN)
	references_secrets(parsed_exprs)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.steps[%d].run", [j, s]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Secrets should be referenced within a dedicated environment",
		"keyActualValue": sprintf("Secret '%s' is accessed outside of a dedicated environment", [parsed_exprs.raw]),
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", format_int(s, 10), "run"], []),
		"resourceType": "github_step",
		"resourceName": sprintf("%s.steps[%d]", [j, s])
	}
}

# Check for secrets usage in step if conditions outside dedicated environments
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	job := doc.jobs[j]

	# Skip if job has an environment defined
	not job.environment
	not job.uses

	# Check step if conditions for secret references
	step := job.steps[s]
	parsed_exprs := step._parsed_expressions_if[_]

	# Verify parsing succeeded
	parsed_exprs.parse_ok == true

	# Check if the expression references secrets (excluding GITHUB_TOKEN)
	references_secrets(parsed_exprs)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.steps[%d].if", [j, s]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Secrets should be referenced within a dedicated environment",
		"keyActualValue": sprintf("Secret '%s' is accessed outside of a dedicated environment", [parsed_exprs.raw]),
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", format_int(s, 10), "if"], []),
		"resourceType": "github_step",
		"resourceName": sprintf("%s.steps[%d]", [j, s])
	}
}

# Check for secrets usage in step env blocks outside dedicated environments
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	job := doc.jobs[j]

	# Skip if job has an environment defined
	not job.environment
	not job.uses

	# Check step env blocks for secret references
	step := job.steps[s]
	env_value := step.env[e]

	# Check if it's a string with parsed expressions
	is_string(env_value)

	# Build the parsed expressions key
	parsed_key := concat("", ["_parsed_expressions_", e])
	parsed_exprs := step.env[parsed_key][_]

	# Verify parsing succeeded
	parsed_exprs.parse_ok == true

	# Check if the expression references secrets (excluding GITHUB_TOKEN)
	references_secrets(parsed_exprs)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.steps[%d].env.%s", [j, s, e]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Secrets should be referenced within a dedicated environment",
		"keyActualValue": sprintf("Secret '%s' is accessed outside of a dedicated environment", [parsed_exprs.raw]),
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", format_int(s, 10), "env", e], []),
		"resourceType": "github_step",
		"resourceName": sprintf("%s.steps[%d]", [j, s])
	}
}

# Check for secrets usage in step with blocks outside dedicated environments
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	job := doc.jobs[j]

	# Skip if job has an environment defined
	not job.environment
	not job.uses

	# Check step with blocks for secret references
	step := job.steps[s]
	with_value := step.with[w]

	# Check if it's a string with parsed expressions
	is_string(with_value)

	# Build the parsed expressions key
	parsed_key := concat("", ["_parsed_expressions_", w])
	parsed_exprs := step.with[parsed_key][_]

	# Verify parsing succeeded
	parsed_exprs.parse_ok == true

	# Check if the expression references secrets (excluding GITHUB_TOKEN)
	references_secrets(parsed_exprs)

	step_name := object.get(step, "name", sprintf("step", [s]))
	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.steps[%d].with.%s", [j, s, w]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Secrets should be referenced within a dedicated environment",
		"keyActualValue": sprintf("Secret '%s' is accessed outside of a dedicated environment", [parsed_exprs.raw]),
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", format_int(s, 10), "with", w], []),
		"resourceType": "github_action",
		"resourceName": step_name
	}
}

# Check for secrets usage in job-level if conditions outside dedicated environments
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	job := doc.jobs[j]

	# Skip if job has an environment defined
	not job.environment
	not job.uses

	# Check job-level if conditions for secret references
	parsed_exprs := job._parsed_expressions_if[_]

	# Verify parsing succeeded
	parsed_exprs.parse_ok == true

	# Check if the expression references secrets (excluding GITHUB_TOKEN)
	references_secrets(parsed_exprs)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.if", [j]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Secrets should be referenced within a dedicated environment",
		"keyActualValue": sprintf("Secret '%s' is accessed outside of a dedicated environment", [parsed_exprs.raw]),
		"searchLine": common_lib.build_search_line(["jobs", j, "if"], []),
		"resourceType": "github_action",
		"resourceName": j
	}
}

# Check for secrets usage in job-level env blocks outside dedicated environments
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	job := doc.jobs[j]

	# Skip if job has an environment defined
	not job.environment
	not job.uses

	# Check job-level env blocks for secret references
	env_value := job.env[e]

	# Check if it's a string with parsed expressions
	is_string(env_value)

	# Build the parsed expressions key
	parsed_key := concat("", ["_parsed_expressions_", e])
	parsed_exprs := job.env[parsed_key][_]

	# Verify parsing succeeded
	parsed_exprs.parse_ok == true

	# Check if the expression references secrets (excluding GITHUB_TOKEN)
	references_secrets(parsed_exprs)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.env.%s", [j, e]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Secrets should be referenced within a dedicated environment",
		"keyActualValue": sprintf("Secret '%s' is accessed outside of a dedicated environment", [parsed_exprs.raw]),
		"searchLine": common_lib.build_search_line(["jobs", j, "env", e], []),
		"resourceType": "github_action",
		"resourceName": j
	}
}

# Helper function to check if an expression references secrets (excluding GITHUB_TOKEN)
references_secrets(parsed_expr) {
	# Check if the raw expression contains "secrets."
	contains(parsed_expr.raw, "secrets.")

	# Exclude GITHUB_TOKEN references
	not contains(parsed_expr.raw, "secrets.GITHUB_TOKEN")
}
