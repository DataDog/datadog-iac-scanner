package Cx

import data.generic.common as common_lib
import data.generic.cicd as cicd_lib

CxPolicy[result] {
	# Only check workflows with dangerous triggers
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	
	cicd_lib.has_dangerous_trigger(doc)

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

# Composite action: write to GITHUB_ENV/GITHUB_PATH is flagged only when the
# appended data traces back to attacker-influenced input — either a `${{ inputs.* }}` /
# `${{ github.event.* }}` template embedded in the arg, or a bash variable whose
# step-level `env` value is interpolated from such a context. Composite actions have
# no doc.on, so we cannot use the workflow rule's dangerous-trigger gate.
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	cicd_lib.is_composite_action(doc)

	step := doc.runs.steps[s]

	run_block := step.run
	is_string(run_block)

	writes_to_env_file(step, run_block)
	composite_env_write_is_tainted(step)
	step_name := object.get(step, "name", sprintf("step-%d", [s]))

	result := {
		"documentId": doc.id,
		"resourceType": "github_action",
		"resourceName": step_name,
		"searchKey": sprintf("runs.steps[%d].run", [s]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Step should not write to GITHUB_ENV or GITHUB_PATH with potentially unsafe data",
		"keyActualValue": "Step writes to GITHUB_ENV or GITHUB_PATH which may allow code execution",
		"searchLine": common_lib.build_search_line(["runs", "steps", s, "run"], []),
	}
}

# Set of args written to GITHUB_ENV / GITHUB_PATH by `step`, either via a direct
# redirect or via a pipeline whose tail is `tee`. Returned as a set so a step that
# writes multiple args in one redirect (e.g. `echo FOO=$M BAR=baz >> $GITHUB_ENV`)
# does not violate Rego's complete-function single-output rule.
composite_env_write_args(step) = args {
	args := {arg |
		step._parsed_run.parse_ok == true
		command := step._parsed_run.commands[_]
		command.type == "redirected_statement"
		command.redirect.operator == [">>", ">"][_]
		command.redirect.target.var == ["GITHUB_ENV", "GITHUB_PATH"][_]
		arg := command.args[_]
	} | {arg |
		step._parsed_run.parse_ok == true
		command := step._parsed_run.commands[_]
		command.type == "pipeline"
		tee_cmd := command.pipeline[_]
		tee_cmd.command == "tee"
		tee_arg := tee_cmd.args[_]
		tee_arg.var == ["GITHUB_ENV", "GITHUB_PATH"][_]
		src_cmd := command.pipeline[_]
		src_cmd.command != "tee"
		arg := src_cmd.args[_]
	}
}

# Bash AST: arg is a simple `$VAR` expansion of a bash var backed by tainted step.env.
composite_env_write_is_tainted(step) {
	arg := composite_env_write_args(step)[_]
	arg.type == "simple_expansion"
	composite_step_env_is_untrusted(step, arg.var)
}

# Bash AST: arg's text expands `$VAR` / `${VAR}` for a bash var backed by tainted step.env.
composite_env_write_is_tainted(step) {
	arg := composite_env_write_args(step)[_]
	matches := regex.find_all_string_submatch_n("\\$\\{?([A-Za-z_][A-Za-z0-9_]*)\\}?", arg.value, -1)
	var_name := matches[_][1]
	composite_step_env_is_untrusted(step, var_name)
}

# Bash AST: arg embeds a `${{ inputs.* }}` / `${{ github.event.* }}` template directly.
composite_env_write_is_tainted(step) {
	arg := composite_env_write_args(step)[_]
	cicd_lib.references_untrusted_context(arg.value)
}

# Regex fallback for shells with no AST (PowerShell / cmd): we cannot tie a template
# to a specific redirect, so conservatively flag any untrusted reference in the run.
composite_env_write_is_tainted(step) {
	not step._parsed_run.parse_ok
	parsed := step._parsed_expressions_run[_]
	parsed.parse_ok == true
	cicd_lib.references_untrusted_context(parsed.raw)
}

composite_step_env_is_untrusted(step, var_name) {
	parsed_key := concat("", ["_parsed_expressions_", var_name])
	parsed := step.env[parsed_key][_]
	parsed.parse_ok == true
	cicd_lib.references_untrusted_context(parsed.raw)
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
