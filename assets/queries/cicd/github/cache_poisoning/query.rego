package Cx

import data.generic.common as common_lib
import data.generic.cicd as cicd_lib
import future.keywords.in

# Known cache-aware actions that can be exploited in cache poisoning attacks
# Format: {"action": {"disable_field": "field_name", "disable_value": value, "type": "opt_in|opt_out"}}
cache_aware_actions := {
	"actions/cache": {"disable_field": "lookup-only", "disable_value": true, "type": "opt_out"},
	"actions/setup-java": {"disable_field": "cache", "disable_value": "", "type": "opt_in_string"},
	"actions/setup-go": {"disable_field": "cache", "disable_value": false, "type": "opt_in"},
	"actions/setup-node": {"disable_field": "package-manager-cache", "disable_value": false, "type": "opt_out"},
	"actions/setup-python": {"disable_field": "cache", "disable_value": "", "type": "opt_in_string"},
	"actions/setup-dotnet": {"disable_field": "cache", "disable_value": false, "type": "opt_in"},
	"astral-sh/setup-uv": {"disable_field": "enable-cache", "disable_value": false, "type": "opt_in"},
	"Swatinem/rust-cache": {"disable_field": "lookup-only", "disable_value": true, "type": "opt_out"},
	"ruby/setup-ruby": {"disable_field": "bundler-cache", "disable_value": false, "type": "opt_in"},
	"PyO3/maturin-action": {"disable_field": "sccache", "disable_value": false, "type": "opt_in"},
	"mlugg/setup-zig": {"disable_field": "use-cache", "disable_value": false, "type": "opt_in"},
	"oven-sh/setup-bun": {"disable_field": "no-cache", "disable_value": true, "type": "opt_out"},
	"DeterminateSystems/magic-nix-cache-action": {"disable_field": "use-gha-cache", "disable_value": false, "type": "opt_in"},
	"graalvm/setup-graalvm": {"disable_field": "cache", "disable_value": "", "type": "opt_in_string"},
	"gradle/actions/setup-gradle": {"disable_field": "cache-disabled", "disable_value": true, "type": "opt_out"},
	"docker/setup-buildx-action": {"disable_field": "cache-binary", "disable_value": false, "type": "opt_in"},
	"actions-rust-lang/setup-rust-toolchain": {"disable_field": "cache", "disable_value": false, "type": "opt_in"},
	"Mozilla-Actions/sccache-action": {"disable_field": null, "type": "not_configurable"},
	"nix-community/cache-nix-action": {"disable_field": null, "type": "not_configurable"},
	"jdx/mise-action": {"disable_field": "cache", "disable_value": false, "type": "opt_in"},
	"ramsey/composer-install": {"disable_field": "ignore-cache", "disable_value": "yes", "type": "opt_out_string"},
}

# Known publisher actions that indicate artifacts are being published
publisher_actions := {
	"pypa/gh-action-pypi-publish",
	"rubygems/release-gem",
	"jreleaser/release-action",
	"goreleaser/goreleaser-action",
	"softprops/action-gh-release",
	"release-drafter/release-drafter",
	"googleapis/release-please-action",
	"docker/build-push-action",
	"redhat-actions/push-to-registry",
	"aws-actions/amazon-ecs-deploy-task-definition",
	"aws-actions/aws-cloudformation-github-deploy",
	"Azure/aci-deploy",
	"Azure/container-apps-deploy-action",
	"Azure/functions-action",
	"Azure/sql-action",
	"cloudflare/wrangler-action",
	"google-github-actions/deploy-appengine",
	"google-github-actions/deploy-cloudrun",
	"google-github-actions/deploy-cloud-functions",
}

# Check if the workflow trigger is used for publishing artifacts
is_publishing_trigger(trigger) = true {
	trigger == "release"
} else = true {
	is_array(trigger)
	trigger[_] == "release"
} else = true {
	trigger.release
} else = true {
	# Check for push with tags
	trigger.push.tags
} else = true {
	# Check for push to release branches
	trigger.push.branches
	some branch in trigger.push.branches
	contains(lower(branch), "release")
} else = false {
	true
}

push_disabled(step) = true {
	startswith(step.uses, "docker/build-push-action")
	not step.with.push
} else = false {
	true
}

# Check if a step uses a known publisher action
uses_publisher_action(step) {
	some action in publisher_actions
	startswith(step.uses, action)
	not push_disabled(step)
}

# Check if action uses match (handles versions)
action_matches(uses, pattern) {
	startswith(uses, pattern)
}

# Check if a step uses a cache-aware action and if caching is enabled
uses_cache_with_config(step) = result {
	step.uses
	some action, config in cache_aware_actions
	action_matches(step.uses, action)

	result := {
		"action": action,
		"config": config,
		"is_enabled": is_cache_enabled(step, config),
	}
}

# Determine if caching is enabled based on action configuration
is_cache_enabled(step, config) {
	# Not configurable actions always use cache
	config.type == "not_configurable"
}

is_cache_enabled(step, config) {
	# Opt-out actions enable cache by default
	config.type == "opt_out"
	not object.get(step, "with", false)
}

is_cache_enabled(step, config) {
	# Opt-out actions enable cache by default
	config.type == "opt_out"
	not step["with"][config.disable_field] == config.disable_value
}

is_cache_enabled(step, config) {
	# Opt-in actions with explicit enable
	config.type == "opt_in"
	step["with"][config.disable_field] == true
}

is_cache_enabled(step, config) {
	# Opt-in string actions with non-empty value
	config.type == "opt_in_string"
	value := step["with"][config.disable_field]
	value != ""
	value != null
}

is_cache_enabled(step, config) {
	# Opt-out actions enable cache by default
	config.type == "opt_out_string"
	not object.get(step, "with", false)
}

is_cache_enabled(step, config) {
	# Opt-out string actions without the disable value
	config.type == "opt_out_string"
	value := step["with"][config.disable_field]
	value != config.disable_value
}

# Check if job has publisher action
has_publisher_action(job) {
	some step in job.steps
	uses_publisher_action(step)
}

publishing_check(publishing_trigger, job) {
	publishing_trigger
} else {
	has_publisher_action(job)
}

# Main policy: Flag cache-aware actions in publishing workflows
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	job := doc.jobs[j]

	# Check if this is a publishing workflow
	is_publishing := is_publishing_trigger(doc.on)

	publishing_check(is_publishing, job)

	# Find cache-aware steps
	step := job.steps[k]
	cache_info := uses_cache_with_config(step)
	cache_info.is_enabled
	step_name := object.get(step, "name", sprintf("step-%d", [k]))

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.steps[%d].uses={{%s}}", [j, k, step.uses]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Cache-aware actions should disable caching in publishing workflows",
		"keyActualValue": sprintf("Step uses %s with caching enabled in a publishing workflow", [cache_info.action]),
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "uses"], []),
		"resourceType": "github_action",
		"resourceName": step_name
	}
}
