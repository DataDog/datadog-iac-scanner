package Cx

import data.generic.common as common_lib

CxPolicy[result] {
	# Only check workflows with dangerous triggers
	doc := input.document[i]
	has_dangerous_trigger(doc)

	job := doc.jobs[j]
	step := job.steps[s]

	run_block := step.run
	is_string(run_block)

	# Check if it writes to GITHUB_ENV or GITHUB_PATH
	writes_to_env_file(step, run_block)
	step_name := object.get(step, "name", sprintf("step-%d", [s]))

	result := {
		"documentId": doc.id,
		"resourceType": "github_action",
		"resourceName": step_name,
		"searchKey": sprintf("jobs.%s.steps[%d].run", [j, s]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Step should not write to GITHUB_ENV or GITHUB_PATH with potentially unsafe data",
		"keyActualValue": "Step writes to GITHUB_ENV or GITHUB_PATH which may allow code execution",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", s, "run"], []),
	}
}


# Check if workflow has dangerous triggers
has_dangerous_trigger(doc) {
	trigger := doc.on
	trigger == ["pull_request_target", "workflow_run"][_]
}

has_dangerous_trigger(doc) {
	trigger := doc.on[_]
	trigger == ["pull_request_target", "workflow_run"][_]
}

has_dangerous_trigger(doc) {
	is_object(doc.on[trigger])
	trigger == ["pull_request_target", "workflow_run"][_]
}

# Detect writes to GITHUB_ENV or GITHUB_PATH using tree-sitter parsed data (bash/sh/zsh)
writes_to_env_file(step, run_block) {
	parsed := step._parsed_run
	parsed.parse_ok == true

	command := parsed.commands[_]

	# Check redirected statements
	command.type == "redirected_statement"
	command.redirect.operator == [">>", ">"][_]
	command.redirect.target.var == ["GITHUB_ENV", "GITHUB_PATH"][_]

	# Ensure at least one argument contains variable expansion (not just literals)
	has_unsafe_content(command)
}

writes_to_env_file(step, run_block) {
	parsed := step._parsed_run
	parsed.parse_ok == true

	command := parsed.commands[_]

	# Check pipeline with tee command
	command.type == "pipeline"
	tee_cmd := command.pipeline[_]
	tee_cmd.command == "tee"
	arg := tee_cmd.args[_]
	arg.var == ["GITHUB_ENV", "GITHUB_PATH"][_]
}

# Fallback: Detect writes using regex patterns for PowerShell/cmd or unparsed shells
writes_to_env_file(step, run_block) {
	# Only use regex fallback if tree-sitter parsing failed or not available
	not step._parsed_run.parse_ok

	# PowerShell patterns: Out-File, Add-Content, Set-Content, Tee-Object
	regex.match(`(?i)(Out-File|Add-Content|Set-Content|Tee-Object).*\$env:(GITHUB_ENV|GITHUB_PATH)`, run_block)
}

writes_to_env_file(step, run_block) {
	not step._parsed_run.parse_ok

	# PowerShell with braces: ${env:GITHUB_ENV}
	regex.match(`(?i)(Out-File|Add-Content|Set-Content|Tee-Object).*\$\{env:(GITHUB_ENV|GITHUB_PATH)\}`, run_block)
}

writes_to_env_file(step, run_block) {
	not step._parsed_run.parse_ok

	# PowerShell redirection: >> $env:GITHUB_ENV
	regex.match(`(?i)>>\s*["']?\$\{?env:(GITHUB_ENV|GITHUB_PATH)\}?["']?`, run_block)
}

writes_to_env_file(step, run_block) {
	not step._parsed_run.parse_ok

	# CMD/batch patterns: >> %GITHUB_ENV%
	regex.match(`(?i)>>\s*["']?%(GITHUB_ENV|GITHUB_PATH)%["']?`, run_block)
}

# Check if command has unsafe content (variable expansions or complex expressions)
has_unsafe_content(command) {
	arg := command.args[_]
	arg.type != "literal"  # Has variable expansion or complex expression
}

has_unsafe_content(command) {
	# Also flag if there are no args at all (e.g., "cat file >> $GITHUB_ENV")
	count(command.args) == 0
}
