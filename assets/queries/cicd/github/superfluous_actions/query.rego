package Cx

import data.generic.cicd as cicd_lib
import data.generic.common as common_lib

# List of superfluous actions that have better alternatives
# These actions provide functionality already available in GitHub-hosted runners

superfluous_actions := {
	"ncipollo/release-action": "use 'gh release' command in a script step",
	"softprops/action-gh-release": "use 'gh release' command in a script step",
	"elgohr/Github-Release-Action": "use 'gh release' command in a script step",
	"peter-evans/create-pull-request":  "use 'gh pr create' in a script step",
	"peter-evans/create-or-update-comment": "use 'gh pr comment' or 'gh issue comment' in a script step",
	"addnab/docker-run-action": "use 'docker run' in a script step, or use a container step",
	"dtolnay/rust-toolchain": "use 'rustup' and/or 'cargo' in a script step"
}

# Check for usage of superfluous actions
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	job := doc.jobs[j]
	step := job.steps[s]

	# Get the uses value
	step_uses := step.uses

	# Check if it matches any superfluous action (allow any version/ref)
	recommendation := superfluous_actions[action_pattern]

	# Extract owner/repo from uses (before @ symbol)
	uses_parts := split(step_uses, "@")
	owner_repo := uses_parts[0]

	# Check if this matches a superfluous action
	owner_repo == action_pattern

	# Get step name if available
	step_name := object.get(step, "name", sprintf("step-%d", [s]))

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.steps[%d].uses={{%s}}", [j, s, owner_repo]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("Use built-in runner functionality instead of this action: %s", [recommendation]),
		"keyActualValue": sprintf("Step '%s' uses superfluous action that duplicates runner functionality", [step_name]),
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", s, "uses"], []),
		"resourceType": "github_step",
		"resourceName": step_name
	}
}

# Composite action: detect superfluous third-party `uses` in `runs.steps[*]`.
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	
	cicd_lib.is_composite_action(doc)

	step := doc.runs.steps[s]
	step_uses := step.uses

	recommendation := superfluous_actions[action_pattern]

	uses_parts := split(step_uses, "@")
	owner_repo := uses_parts[0]

	owner_repo == action_pattern

	step_name := object.get(step, "name", sprintf("step-%d", [s]))

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("runs.steps[%d].uses={{%s}}", [s, owner_repo]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("Use built-in runner functionality instead of this action: %s", [recommendation]),
		"keyActualValue": sprintf("Step '%s' uses superfluous action that duplicates runner functionality", [step_name]),
		"searchLine": common_lib.build_search_line(["runs", "steps", s, "uses"], []),
		"resourceType": "github_step",
		"resourceName": step_name
	}
}
