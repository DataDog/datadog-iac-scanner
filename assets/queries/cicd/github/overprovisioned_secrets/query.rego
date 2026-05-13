package Cx

import data.generic.common as common_lib
import data.generic.cicd as cicd_lib

# Detect toJSON(secrets) in step run blocks
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	job := doc.jobs[j]
	step := job.steps[s]

	# Check if step has parsed expressions for the run field
	parsed_exprs := step._parsed_expressions_run[_]

	# Verify parsing succeeded and secrets expansion was detected
	parsed_exprs.parse_ok == true
	parsed_exprs.has_secrets_expansion == true

	step_name := object.get(step, "name", sprintf("step", [s]))
	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.steps[%d].run", [j, s]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Secrets should be referenced individually, not as a whole context",
		"keyActualValue": sprintf("Expression '%s' injects the entire secrets context into the runner", [parsed_exprs.raw]),
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", format_int(s, 10), "run"], []),
		"resourceType": "github_action",
		"resourceName": step_name
	}
}

# Detect dynamic secret indexing: secrets[variable] in step run blocks
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	job := doc.jobs[j]
	step := job.steps[s]

	# Check if step has parsed expressions for the run field
	parsed_exprs := step._parsed_expressions_run[_]

	# Verify parsing succeeded and dynamic secret key access was detected
	parsed_exprs.parse_ok == true
	parsed_exprs.has_dynamic_secret_key == true
	step_name := object.get(step, "name", sprintf("step", [s]))

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.steps[%d].run", [j, s]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Secrets should be accessed with literal keys, not dynamic expressions",
		"keyActualValue": sprintf("Expression '%s' uses dynamic indexing to access secrets", [parsed_exprs.raw]),
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", format_int(s, 10), "run"], []),
		"resourceType": "github_action",
		"resourceName": step_name
	}
}

# Detect toJSON(secrets) in job-level if conditions
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	job := doc.jobs[j]

	# Check if job has parsed expressions for the if condition
	parsed_exprs := job._parsed_expressions_if[_]

	# Verify parsing succeeded and secrets expansion was detected
	parsed_exprs.parse_ok == true
	parsed_exprs.has_secrets_expansion == true

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.if", [j]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Secrets should be referenced individually, not as a whole context",
		"keyActualValue": sprintf("Expression '%s' injects the entire secrets context", [parsed_exprs.raw]),
		"searchLine": common_lib.build_search_line(["jobs", j, "if"], []),
		"resourceType": "github_action",
		"resourceName": j
	}
}

# Detect dynamic secret indexing in job-level if conditions
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	job := doc.jobs[j]

	# Check if job has parsed expressions for the if condition
	parsed_exprs := job._parsed_expressions_if[_]

	# Verify parsing succeeded and dynamic secret key access was detected
	parsed_exprs.parse_ok == true
	parsed_exprs.has_dynamic_secret_key == true

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.if", [j]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Secrets should be accessed with literal keys, not dynamic expressions",
		"keyActualValue": sprintf("Expression '%s' uses dynamic indexing to access secrets", [parsed_exprs.raw]),
		"searchLine": common_lib.build_search_line(["jobs", j, "if"], []),
		"resourceType": "github_action",
		"resourceName": j
	}
}

# Detect toJSON(secrets) in step-level if conditions
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	job := doc.jobs[j]
	step := job.steps[s]

	# Check if step has parsed expressions for the if condition
	parsed_exprs := step._parsed_expressions_if[_]

	# Verify parsing succeeded and secrets expansion was detected
	parsed_exprs.parse_ok == true
	parsed_exprs.has_secrets_expansion == true

	step_name := object.get(step, "name", sprintf("step", [s]))
	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.steps[%d].if", [j, s]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Secrets should be referenced individually, not as a whole context",
		"keyActualValue": sprintf("Expression '%s' injects the entire secrets context", [parsed_exprs.raw]),
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", format_int(s, 10), "if"], []),
		"resourceType": "github_action",
		"resourceName": step_name
	}
}

# Detect dynamic secret indexing in step-level if conditions
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	job := doc.jobs[j]
	step := job.steps[s]

	# Check if step has parsed expressions for the if condition
	parsed_exprs := step._parsed_expressions_if[_]

	# Verify parsing succeeded and dynamic secret key access was detected
	parsed_exprs.parse_ok == true
	parsed_exprs.has_dynamic_secret_key == true

	step_name := object.get(step, "name", sprintf("step", [s]))
	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.steps[%d].if", [j, s]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Secrets should be accessed with literal keys, not dynamic expressions",
		"keyActualValue": sprintf("Expression '%s' uses dynamic indexing to access secrets", [parsed_exprs.raw]),
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", format_int(s, 10), "if"], []),
		"resourceType": "github_action",
		"resourceName": step_name
	}
}

# Detect toJSON(secrets) or dynamic secret access in step with blocks (action inputs)
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	job := doc.jobs[j]
	step := job.steps[s]

	# Get the with block
	with_block := step.with
	with_block[w]

	# Check for parsed expressions in any with parameter
	parsed_key := concat("", ["_parsed_expressions_", w])
	parsed_exprs := with_block[parsed_key][_]

	# Verify parsing succeeded
	parsed_exprs.parse_ok == true

	# Check for either secrets expansion or dynamic secret key
	any([parsed_exprs.has_secrets_expansion, parsed_exprs.has_dynamic_secret_key])

	# Build appropriate message
	message := sprintf("Expression '%s' %s", [
		parsed_exprs.raw,
		get_submessage(parsed_exprs.has_secrets_expansion)
	])

	step_name := object.get(step, "name", sprintf("step", [s]))
	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.steps[%d].with.%s", [j, s, w]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Secrets should be referenced individually with literal keys",
		"keyActualValue": message,
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", format_int(s, 10), "with", w], []),
		"resourceType": "github_action",
		"resourceName": step_name
	}
}

# Detect toJSON(secrets) or dynamic secret access in step env blocks
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	job := doc.jobs[j]
	step := job.steps[s]

	# Get the env block
	env_value := step.env[e]

	# Check if it's a string with parsed expressions
	is_string(env_value)

	# Build the parsed expressions key
	parsed_key := concat("", ["_parsed_expressions_", e])
	parsed_exprs := step.env[parsed_key][_]

	# Verify parsing succeeded
	parsed_exprs.parse_ok == true

	# Check for either secrets expansion or dynamic secret key
	any([parsed_exprs.has_secrets_expansion, parsed_exprs.has_dynamic_secret_key])

	# Build appropriate message
	message := sprintf("Expression '%s' %s", [
		parsed_exprs.raw,
		get_submessage(parsed_exprs.has_secrets_expansion)
	])

	step_name := object.get(step, "name", sprintf("step", [s]))
	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.steps[%d].env.%s", [j, s, e]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Secrets should be referenced individually with literal keys",
		"keyActualValue": message,
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", format_int(s, 10), "env", e], []),
		"resourceType": "github_action",
		"resourceName": step_name
	}
}

# Detect toJSON(secrets) or dynamic secret access in job-level env blocks
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	job := doc.jobs[j]

	# Get the env block
	env_value := job.env[e]

	# Check if it's a string with parsed expressions
	is_string(env_value)

	# Build the parsed expressions key
	parsed_key := concat("", ["_parsed_expressions_", e])
	parsed_exprs := job.env[parsed_key][_]

	# Verify parsing succeeded
	parsed_exprs.parse_ok == true

	# Check for either secrets expansion or dynamic secret key
	any([parsed_exprs.has_secrets_expansion, parsed_exprs.has_dynamic_secret_key])

	# Build appropriate message
	message := sprintf("Expression '%s' %s", [
		parsed_exprs.raw,
		get_submessage(parsed_exprs.has_secrets_expansion)
	])

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.env.%s", [j, e]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Secrets should be referenced individually with literal keys",
		"keyActualValue": message,
		"searchLine": common_lib.build_search_line(["jobs", j, "env", e], []),
		"resourceType": "github_action",
		"resourceName": j
	}
}

# Detect toJSON(secrets) or dynamic secret access in root env block
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	env := doc.env

	# Get the env block
	env_value := env[e]

	# Check if it's a string with parsed expressions
	is_string(env_value)

	# Build the parsed expressions key
	parsed_key := concat("", ["_parsed_expressions_", e])
	parsed_exprs := env[parsed_key][_]

	# Verify parsing succeeded
	parsed_exprs.parse_ok == true

	# Check for either secrets expansion or dynamic secret key
	any([parsed_exprs.has_secrets_expansion, parsed_exprs.has_dynamic_secret_key])

	# Build appropriate message
	message := sprintf("Expression '%s' %s", [
		parsed_exprs.raw,
		get_submessage(parsed_exprs.has_secrets_expansion)
	])

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("env.%s", [e]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Secrets should be referenced individually with literal keys",
		"keyActualValue": message,
		"searchLine": common_lib.build_search_line(["env", e], []),
		"resourceType": "github_action",
		"resourceName": "env"
	}
}

get_submessage(has_secrets_expansion) = "injects the entire secrets context" {
	has_secrets_expansion
} else = "uses dynamic indexing to access secrets" {
	true
}
