package Cx

import future.keywords.in
import data.generic.common as common_lib

# Check for known actions using manual credentials
CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j]
	is_object(job)

	steps := job.steps
	is_array(steps)
	step := steps[s]

	uses := step.uses
	is_string(uses)

	# Check known actions that should use trusted publishing
	check_pypi_action(step, uses)

	result := {
		"documentId": doc.id,
		"resourceType": "github_action",
		"resourceName": j,
		"searchKey": sprintf("jobs.%s.steps[%d].with.password", [j, s]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Step should use Trusted Publishing instead of manual credentials",
		"keyActualValue": "Step uses manually-configured password for PyPI publishing",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", s, "with"], ["password"]),
	}
}

CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j]
	is_object(job)

	steps := job.steps
	is_array(steps)
	step := steps[s]

	uses := step.uses
	is_string(uses)

	check_rubygems_release_action(step, uses)

	result := {
		"documentId": doc.id,
		"resourceType": "github_action",
		"resourceName": j,
		"searchKey": sprintf("jobs.%s.steps[%d].uses", [j, s]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Step should set setup-trusted-publisher: true",
		"keyActualValue": "Step does not use Trusted Publishing for RubyGems",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", s], ["uses"]),
	}
}

CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j]
	is_object(job)

	steps := job.steps
	is_array(steps)
	step := steps[s]

	uses := step.uses
	is_string(uses)

	check_rubygems_credentials_action(step, uses)

	result := {
		"documentId": doc.id,
		"resourceType": "github_action",
		"resourceName": j,
		"searchKey": sprintf("jobs.%s.steps[%d].with.api-token", [j, s]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Step should use Trusted Publishing instead of manual api-token",
		"keyActualValue": "Step uses manually-configured api-token for RubyGems",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", s, "with"], ["api-token"]),
	}
}

CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j]
	is_object(job)

	steps := job.steps
	is_array(steps)
	step := steps[s]

	uses := step.uses
	is_string(uses)

	check_npm_setup_action(step, uses)

	result := {
		"documentId": doc.id,
		"resourceType": "github_action",
		"resourceName": j,
		"searchKey": sprintf("jobs.%s.steps[%d].with.always-auth", [j, s]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Step should use Trusted Publishing instead of always-auth with manual tokens",
		"keyActualValue": "Step uses always-auth with manual authentication for npm",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", s, "with"], ["always-auth"]),
	}
}

# Check for publishing commands in run blocks without id-token permission
CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j]
	is_object(job)

	steps := job.steps
	is_array(steps)
	step := steps[s]

	run_block := step.run
	is_string(run_block)

	# Detect publishing command
	has_publishing_command(step, run_block)

	# Check that job doesn't have id-token: write permission
	not has_id_token_permission(doc, job)

	result := {
		"documentId": doc.id,
		"resourceType": "github_action",
		"resourceName": j,
		"searchKey": sprintf("jobs.%s.steps[%d].run", [j, s]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Publishing command should use Trusted Publishing (requires id-token: write permission)",
		"keyActualValue": "Publishing command runs without id-token permission, likely using manual credentials",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", s], ["run"]),
	}
}

# PyPI action: pypa/gh-action-pypi-publish with password
check_pypi_action(step, uses) {
	regex.match(`pypa/gh-action-pypi-publish`, uses)
	step["with"].password
}

# RubyGems release action: without setup-trusted-publisher
check_rubygems_release_action(step, uses) {
	regex.match(`rubygems/release-gem`, uses)
	with_block := step["with"]
	not with_block["setup-trusted-publisher"]
}

check_rubygems_release_action(step, uses) {
	regex.match(`rubygems/release-gem`, uses)
	with_block := step["with"]
	with_block["setup-trusted-publisher"] == false
}

check_rubygems_release_action(step, uses) {
	regex.match(`rubygems/release-gem`, uses)
	not step["with"]
}

# RubyGems credentials action: with api-token for rubygems.org
check_rubygems_credentials_action(step, uses) {
	regex.match(`rubygems/configure-rubygems-credentials`, uses)
	step["with"]["api-token"]

	# Check if gem-server is rubygems.org (or not specified, which defaults to it)
	gem_server := object.get(step["with"], "gem-server", "https://rubygems.org")
	gem_server == "https://rubygems.org"
}

# npm setup-node action: with always-auth for npmjs registry
check_npm_setup_action(step, uses) {
	regex.match(`actions/setup-node`, uses)
	with_block := step["with"]

	# Check for always-auth: true
	always_auth := object.get(with_block, "always-auth", false)
	always_auth == true

	# Check if registry is npmjs
	registry_url := object.get(with_block, "registry-url", "")
	regex.match(`(?i)registry\.npmjs\.org`, registry_url)
}

# Detect publishing commands using tree-sitter parsed data (bash/sh/zsh)
has_publishing_command(step, _) {
	parsed := step._parsed_run
	parsed.parse_ok == true

	command := parsed.commands[_]

	# Check for Rust/Cargo: cargo publish (without --dry-run)
	command.command == "cargo"
	has_arg_matching(command, "publish")
	not has_dry_run_flag(command)
}

has_publishing_command(step, _) {
	parsed := step._parsed_run
	parsed.parse_ok == true

	command := parsed.commands[_]

	# Check for Python/uv: uv publish (without --dry-run)
	command.command == "uv"
	has_arg_matching(command, "publish")
	not has_dry_run_flag(command)
}

has_publishing_command(step, _) {
	parsed := step._parsed_run
	parsed.parse_ok == true

	command := parsed.commands[_]

	# Check for Python/uv: uv run twine upload
	command.command == "uv"
	has_arg_matching(command, "run")
	has_arg_matching(command, "twine")
	has_arg_matching(command, "upload")
}

has_publishing_command(step, _) {
	parsed := step._parsed_run
	parsed.parse_ok == true

	command := parsed.commands[_]

	# Check for Python/uvx: uvx twine upload
	command.command == "uvx"
	has_arg_matching(command, "twine")
	has_arg_matching(command, "upload")
}

has_publishing_command(step, _) {
	parsed := step._parsed_run
	parsed.parse_ok == true

	command := parsed.commands[_]

	# Check for Python/hatch: hatch publish
	command.command == "hatch"
	has_arg_matching(command, "publish")
}

has_publishing_command(step, _) {
	parsed := step._parsed_run
	parsed.parse_ok == true

	command := parsed.commands[_]

	# Check for Python/pdm: pdm publish
	command.command == "pdm"
	has_arg_matching(command, "publish")
}

has_publishing_command(step, _) {
	parsed := step._parsed_run
	parsed.parse_ok == true

	command := parsed.commands[_]

	# Check for Python/poetry: poetry publish (without --dry-run)
	command.command == "poetry"
	has_arg_matching(command, "publish")
	not has_dry_run_flag(command)
}

has_publishing_command(step, _) {
	parsed := step._parsed_run
	parsed.parse_ok == true

	command := parsed.commands[_]

	# Check for Python/twine: twine upload
	command.command == "twine"
	has_arg_matching(command, "upload")
}

has_publishing_command(step, _) {
	parsed := step._parsed_run
	parsed.parse_ok == true

	command := parsed.commands[_]

	# Check for Python/pipx: pipx run twine upload
	command.command == "pipx"
	has_arg_matching(command, "run")
	has_arg_matching(command, "twine")
	has_arg_matching(command, "upload")
}

has_publishing_command(step, _) {
	parsed := step._parsed_run
	parsed.parse_ok == true

	command := parsed.commands[_]

	# Check for Python module: python -m twine upload
	regex.match(`^python[0-9.]*$`, command.command)
	has_arg_matching(command, "-m")
	has_arg_matching(command, "twine")
	has_arg_matching(command, "upload")
}

has_publishing_command(step, _) {
	parsed := step._parsed_run
	parsed.parse_ok == true

	command := parsed.commands[_]

	# Check for Ruby/gem: gem push
	command.command == "gem"
	has_arg_matching(command, "push")
}

has_publishing_command(step, _) {
	parsed := step._parsed_run
	parsed.parse_ok == true

	command := parsed.commands[_]

	# Check for Ruby/bundle: bundle exec gem push
	command.command == "bundle"
	has_arg_matching(command, "exec")
	has_arg_matching(command, "gem")
	has_arg_matching(command, "push")
}

has_publishing_command(step, _) {
	parsed := step._parsed_run
	parsed.parse_ok == true

	command := parsed.commands[_]

	# Check for npm: npm publish (without --dry-run)
	command.command == "npm"
	has_arg_matching(command, "publish")
	not has_dry_run_flag(command)
}

has_publishing_command(step, _) {
	parsed := step._parsed_run
	parsed.parse_ok == true

	command := parsed.commands[_]

	# Check for yarn: yarn publish or yarn npm publish (without --dry-run)
	command.command == "yarn"
	has_arg_matching(command, "publish")
	not has_dry_run_flag(command)
}

has_publishing_command(step, _) {
	parsed := step._parsed_run
	parsed.parse_ok == true

	command := parsed.commands[_]

	# Check for pnpm: pnpm publish (without --dry-run)
	command.command == "pnpm"
	has_arg_matching(command, "publish")
	not has_dry_run_flag(command)
}

has_publishing_command(step, _) {
	parsed := step._parsed_run
	parsed.parse_ok == true

	command := parsed.commands[_]

	# Check for .NET/NuGet: nuget push or dotnet nuget push
	command.command in ["nuget", "nuget.exe"]
	has_arg_matching(command, "push")
}

has_publishing_command(step, _) {
	parsed := step._parsed_run
	parsed.parse_ok == true

	command := parsed.commands[_]

	# Check for .NET/NuGet: dotnet nuget push
	command.command == "dotnet"
	has_arg_matching(command, "nuget")
	has_arg_matching(command, "push")
}

# Fallback: Detect publishing commands using regex patterns for PowerShell/cmd or unparsed shells
has_publishing_command(step, run_block) {
	# Only use regex fallback if tree-sitter parsing failed or not available
	not step._parsed_run.parse_ok

	# Rust/Cargo: cargo publish (without --dry-run)
	regex.match(`(?i)\bcargo\s+.*publish`, run_block)
	not regex.match(`(?i)--dry-run|-n`, run_block)
}

has_publishing_command(step, run_block) {
	not step._parsed_run.parse_ok

	# Python/uv: uv publish (without --dry-run)
	regex.match(`(?i)\buv\s+.*publish`, run_block)
	not regex.match(`(?i)--dry-run`, run_block)
}

has_publishing_command(step, run_block) {
	not step._parsed_run.parse_ok

	# Python/uv: uv run twine upload
	regex.match(`(?i)\buv\s+run\s+.*twine.*upload`, run_block)
}

has_publishing_command(step, run_block) {
	not step._parsed_run.parse_ok

	# Python/uvx: uvx twine upload
	regex.match(`(?i)\buvx\s+twine.*upload`, run_block)
}

has_publishing_command(step, run_block) {
	not step._parsed_run.parse_ok

	# Python/hatch: hatch publish
	regex.match(`(?i)\bhatch\s+.*publish`, run_block)
}

has_publishing_command(step, run_block) {
	not step._parsed_run.parse_ok

	# Python/pdm: pdm publish
	regex.match(`(?i)\bpdm\s+.*publish`, run_block)
}

has_publishing_command(step, run_block) {
	not step._parsed_run.parse_ok

	# Python/poetry: poetry publish (without --dry-run)
	regex.match(`(?i)\bpoetry\s+.*publish`, run_block)
	not regex.match(`(?i)--dry-run`, run_block)
}

has_publishing_command(step, run_block) {
	not step._parsed_run.parse_ok

	# Python/twine: twine upload
	regex.match(`(?i)\btwine\s+.*upload`, run_block)
}

has_publishing_command(step, run_block) {
	not step._parsed_run.parse_ok

	# Python/pipx: pipx run twine upload
	regex.match(`(?i)\bpipx\s+run\s+.*twine.*upload`, run_block)
}

has_publishing_command(step, run_block) {
	not step._parsed_run.parse_ok

	# Python module: python -m twine upload
	regex.match(`(?i)\bpython[0-9.]*\s+-m\s+twine\s+.*upload`, run_block)
}

has_publishing_command(step, run_block) {
	not step._parsed_run.parse_ok

	# Ruby/gem: gem push
	regex.match(`(?i)\bgem\s+push`, run_block)
}

has_publishing_command(step, run_block) {
	not step._parsed_run.parse_ok

	# Ruby/bundle: bundle exec gem push
	regex.match(`(?i)\bbundle\s+exec\s+gem\s+push`, run_block)
}

has_publishing_command(step, run_block) {
	not step._parsed_run.parse_ok

	# npm: npm publish (without --dry-run)
	regex.match(`(?i)\bnpm\s+.*publish`, run_block)
	not regex.match(`(?i)--dry-run`, run_block)
}

has_publishing_command(step, run_block) {
	not step._parsed_run.parse_ok

	# yarn: yarn publish or yarn npm publish (without --dry-run)
	regex.match(`(?i)\byarn\s+(npm\s+)?publish`, run_block)
	not regex.match(`(?i)--dry-run|-n`, run_block)
}

has_publishing_command(step, run_block) {
	not step._parsed_run.parse_ok

	# pnpm: pnpm publish (without --dry-run)
	regex.match(`(?i)\bpnpm\s+.*publish`, run_block)
	not regex.match(`(?i)--dry-run`, run_block)
}

has_publishing_command(step, run_block) {
	not step._parsed_run.parse_ok

	# .NET/NuGet: nuget push or dotnet nuget push
	regex.match(`(?i)\b(nuget|dotnet\s+nuget)(\.exe)?\s+push`, run_block)
}

# Helper: Check if command has an argument matching a value
has_arg_matching(command, value) {
	arg := command.args[_]
	lower(arg.value) == lower(value)
}

# Helper: Check if command has dry-run flag
has_dry_run_flag(command) {
	arg := command.args[_]
	arg.value in ["--dry-run", "-n"]
}

# Check if job has id-token: write permission
has_id_token_permission(doc, job) {
	permissions := job.permissions
	permissions["id-token"] == "write"
}

has_id_token_permission(doc, job) {
	# Check workflow-level permissions
	permissions := doc.permissions
	permissions["id-token"] == "write"
}
