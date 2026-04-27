package Cx

import data.generic.cicd as cicd_lib
import data.generic.common as common_lib
import data.generic.cicd as cicd_lib

# Check for actions/setup-python with pip-install input
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"

	job := doc.jobs[j]
	step := job.steps[s]

	# Check if step uses actions/setup-python
	step_uses := step.uses
	startswith(step_uses, "actions/setup-python")

	# Check if pip-install input is present
	value := step.with[key]
	key == "pip-install"

	# Get step name if available
	step_name := object.get(step, "name", sprintf("step-%d", [s]))

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.steps[%d].with.pip-install", [j, s]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Python packages should be installed in a virtual environment, not using pip-install input",
		"keyActualValue": sprintf("Step '%s' uses pip-install input which installs packages in a brittle manner", [step_name]),
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", s, "with", "pip-install"], []),
		"resourceType": "github_action",
		"resourceName": step_name,
	}
}

# Check for shell: cmd usage
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"

	job := doc.jobs[j]
	step := job.steps[s]

	# Check if step has a run block
	step.run

	# Check if shell is cmd or cmd.exe
	shell := object.get(step, "shell", "")
	["cmd", "cmd.exe"][_] == shell

	# Get step name if available
	step_name := object.get(step, "name", sprintf("step-%d", [s]))

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.steps[%d].shell={{%s}}", [j, s, shell]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Use 'shell: pwsh' or 'shell: bash' for improved analysis and reliability",
		"keyActualValue": sprintf("Step '%s' uses Windows CMD shell which limits security analysis", [step_name]),
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", s, "shell"], []),
		"resourceType": "github_action",
		"resourceName": step_name,
	}
}

# Composite GitHub Action: actions/setup-python with pip-install input.
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"

	cicd_lib.is_composite_action(doc)

	step := doc.runs.steps[s]

	step_uses := step.uses
	startswith(step_uses, "actions/setup-python")

	value := step.with[key]
	key == "pip-install"

	step_name := object.get(step, "name", sprintf("step-%d", [s]))

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("runs.steps[%d].with.pip-install", [s]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Python packages should be installed in a virtual environment, not using pip-install input",
		"keyActualValue": sprintf("Step '%s' uses pip-install input which installs packages in a brittle manner", [step_name]),
		"searchLine": common_lib.build_search_line(["runs", "steps", s, "with", "pip-install"], []),
		"resourceType": "github_action",
		"resourceName": step_name,
	}
}

# Composite GitHub Action: shell: cmd usage in a step run block.
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	
	cicd_lib.is_composite_action(doc)

	step := doc.runs.steps[s]
	step.run

	shell := object.get(step, "shell", "")
	["cmd", "cmd.exe"][_] == shell

	step_name := object.get(step, "name", sprintf("step-%d", [s]))

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("runs.steps[%d].shell={{%s}}", [s, shell]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Use 'shell: pwsh' or 'shell: bash' for improved analysis and reliability",
		"keyActualValue": sprintf("Step '%s' uses Windows CMD shell which limits security analysis", [step_name]),
		"searchLine": common_lib.build_search_line(["runs", "steps", s, "shell"], []),
		"resourceType": "github_action",
		"resourceName": step_name,
	}
}
