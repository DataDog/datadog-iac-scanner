package Cx

import data.generic.cicd as cicd_lib
import data.generic.common as common_lib

CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	check_trigger(doc, "pull_request_target")

	run := doc.jobs[j].steps[k].run

	patterns := [
    "github\\.head_ref",
    "github\\.event\\.pull_request\\.body",
    "github\\.event\\.pull_request\\.head\\.label",
    "github\\.event\\.pull_request\\.head\\.ref",
    "github\\.event\\.pull_request\\.head\\.repo\\.default_branch",
    "github\\.event\\.pull_request\\.head\\.repo\\.description",
    "github\\.event\\.pull_request\\.head\\.repo\\.homepage",
    "github\\.event\\.pull_request\\.title"
	]

	matched = containsPatterns(run, patterns)
	count(matched) > 0

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("run={{%s}}", [run]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Run block does not contain dangerous input controlled by user.",
		"keyActualValue": "Run block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "run"],[]),
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	check_trigger(doc, "issues")

	run := doc.jobs[j].steps[k].run

	patterns := [
    "github\\.event\\.issue\\.body",
	"github\\.event\\.issue\\.title"
	]

	matched = containsPatterns(run, patterns)
	count(matched) > 0

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("run={{%s}}", [run]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Run block does not contain dangerous input controlled by user.",
		"keyActualValue": "Run block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "run"],[]),
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	check_trigger(doc, "issue_comment")

	run := doc.jobs[j].steps[k].run

	patterns := [
    "github\\.event\\.comment\\.body",
	"github\\.event\\.issue\\.body",
	"github\\.event\\.issue\\.title"
	]

	matched = containsPatterns(run, patterns)
	count(matched) > 0

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("run={{%s}}", [run]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Run block does not contain dangerous input controlled by user.",
		"keyActualValue": "Run block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "run"],[]),
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	check_trigger(doc, "discussion")

	run := doc.jobs[j].steps[k].run

	patterns := [
    "github\\.event\\.discussion\\.body",
	"github\\.event\\.discussion\\.title"
	]

	matched = containsPatterns(run, patterns)
	count(matched) > 0

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("run={{%s}}", [run]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Run block does not contain dangerous input controlled by user.",
		"keyActualValue": "Run block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "run"],[]),
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	check_trigger(doc, "discussion_comment")

	run := doc.jobs[j].steps[k].run

	patterns := [
    "github\\.event\\.comment\\.body",
	"github\\.event\\.discussion\\.body",
	"github\\.event\\.discussion\\.title"
	]

	matched = containsPatterns(run, patterns)
	count(matched) > 0

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("run={{%s}}", [run]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Run block does not contain dangerous input controlled by user.",
		"keyActualValue": "Run block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "run"],[]),
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	check_trigger(doc, "workflow_run")

	run := doc.jobs[j].steps[k].run

	patterns := [
    "github\\.event\\.workflow\\.path",
	"github\\.event\\.workflow_run\\.head_branch",
	"github\\.event\\.workflow_run\\.head_commit\\.author\\.email",
	"github\\.event\\.workflow_run\\.head_commit\\.author\\.name",
	"github\\.event\\.workflow_run\\.head_commit\\.message",
	"github\\.event\\.workflow_run\\.head_repository\\.description"
	]

	matched = containsPatterns(run, patterns)
	count(matched) > 0

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("run={{%s}}", [run]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Run block does not contain dangerous input controlled by user.",
		"keyActualValue": "Run block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "run"],[]),
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	check_trigger(doc, "author")
	run := doc.jobs[j].steps[k].run

	patterns := [
    "github\\..*\\.authors\\.name",
	"github\\..*\\.authors\\.email"
	]

	matched = containsPatterns(run, patterns)
	count(matched) > 0

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("run={{%s}}", [run]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Run block does not contain dangerous input controlled by user.",
		"keyActualValue": "Run block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "run"],[]),
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	check_trigger(doc, "pull_request")
	run := doc.jobs[j].steps[k].run

	patterns := [
		"github\\.head_ref",
		"github\\.event\\.pull_request\\.head\\.ref",
		"github\\.event\\.pull_request\\.head\\.label",
		"github\\.event\\.pull_request\\.head\\.repo\\..+",
		"github\\.event\\.pull_request\\.title",
		"github\\.event\\.pull_request\\.body",
	]

	matched = containsPatterns(run, patterns)
	count(matched) > 0

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("run={{%s}}", [run]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Run block does not contain dangerous input controlled by user.",
		"keyActualValue": "Run block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "run"],[]),
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	check_trigger(doc, "workflow_dispatch")
	run := doc.jobs[j].steps[k].run

	patterns := [
		"github\\.event\\.inputs\\..+"
	]

	matched = containsPatterns(run, patterns)
	count(matched) > 0

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("run={{%s}}", [run]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Run block does not contain dangerous input controlled by user.",
		"keyActualValue": "Run block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "run"],[]),
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

# Workflow steps: `${{ env.X }}` dereference inside a run block. Skip the finding
# when X is locally defined on the step as a literal (or only-safe interpolation);
# treat unknown keys as unsafe since their value may come from job/workflow env or
# from a previous step's `>> $GITHUB_ENV` write.
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	step := doc.jobs[j].steps[k]
	parsed_run := step._parsed_expressions_run[_]
	run := step.run

	walk(parsed_run, [_, node])

	node.type == "dereference_expression"

	matched := containsPatterns(node.value, ["^env\\."])
	count(matched) > 0

	env_key := step_env_key(node.value)
	not step_env_locally_safe(step, env_key)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("run={{%s}}", [run]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Run block does not contain dangerous input controlled by user.",
		"keyActualValue": "Run block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "run"],[]),
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

# === Composite GitHub Actions (action.yml) ===
# Composite actions live under `runs.steps[*]` (not `jobs[*].steps[*]`) and have no
# `doc.on` — the trigger comes from the caller — so we union all trigger-specific
# patterns into a single check below.

CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	cicd_lib.is_composite_action(doc)

	run := doc.runs.steps[k].run

	patterns := [
		"github\\.head_ref",
		"github\\.event\\.pull_request\\.body",
		"github\\.event\\.pull_request\\.head\\.label",
		"github\\.event\\.pull_request\\.head\\.ref",
		"github\\.event\\.pull_request\\.head\\.repo\\..+",
		"github\\.event\\.pull_request\\.title",
		"github\\.event\\.issue\\.body",
		"github\\.event\\.issue\\.title",
		"github\\.event\\.comment\\.body",
		"github\\.event\\.discussion\\.body",
		"github\\.event\\.discussion\\.title",
		"github\\.event\\.workflow\\.path",
		"github\\.event\\.workflow_run\\.head_branch",
		"github\\.event\\.workflow_run\\.head_commit\\.author\\.email",
		"github\\.event\\.workflow_run\\.head_commit\\.author\\.name",
		"github\\.event\\.workflow_run\\.head_commit\\.message",
		"github\\.event\\.workflow_run\\.head_repository\\.description",
		"github\\..*\\.authors\\.name",
		"github\\..*\\.authors\\.email",
		"github\\.event\\.inputs\\..+",
	]

	matched := containsPatterns(run, patterns)
	count(matched) > 0

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("run={{%s}}", [run]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Run block does not contain dangerous input controlled by user.",
		"keyActualValue": "Run block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["runs", "steps", k, "run"], []),
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.runs.steps[k], k)
	}
}

# Composite action: ${{ inputs.* }} interpolated directly into a run block.
# Driven by the parsed GitHub Actions expression AST so that nested contexts
# such as ${{ github.event.inputs.* }} are handled by the broader rule above
# and do not double-fire here through substring matching of `inputs.`.
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	cicd_lib.is_composite_action(doc)

	step := doc.runs.steps[k]
	parsed_run := step._parsed_expressions_run[_]

	walk(parsed_run, [_, node])
	cicd_lib.is_bare_inputs_dereference(node)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("run={{%s}}", [step.run]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Run block does not directly interpolate composite action inputs into the shell.",
		"keyActualValue": "Run block directly interpolates a composite action input into the shell, which can lead to command injection if the input is attacker-controlled.",
		"searchLine": common_lib.build_search_line(["runs", "steps", k, "run"], []),
		"resourceType": "github_action",
		"resourceName": get_step_name(step, k)
	}
}

# Composite action: ${{ env.X }} dereference inside a run block. Skip the finding
# when X is locally defined on the step as a literal (or only-safe interpolation);
# treat unknown keys as unsafe since their value comes from the caller's workflow.
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	cicd_lib.is_composite_action(doc)
	step := doc.runs.steps[k]
	parsed_run := step._parsed_expressions_run[_]

	walk(parsed_run, [_, node])

	node.type == "dereference_expression"

	matched := containsPatterns(node.value, ["^env\\."])
	count(matched) > 0

	env_key := step_env_key(node.value)
	not step_env_locally_safe(step, env_key)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("run={{%s}}", [parsed_run]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Run block does not contain dangerous input controlled by user.",
		"keyActualValue": "Run block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["runs", "steps", k, "run"], []),
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.runs.steps[k], k)
	}
}

# Extracts `X` from the dereference text `env.X` (or `env.X.Y...`).
step_env_key(node_value) = key {
	parts := split(node_value, ".")
	count(parts) >= 2
	key := parts[1]
}

# True when the step locally defines `env.<env_key>` as a literal string with no
# untrusted-context interpolation. Used by both the workflow-step rule above and
# the composite-action rule below to suppress the env.* finding for clearly safe
# locally-scoped values.
step_env_locally_safe(step, env_key) {
	is_string(step.env[env_key])
	not step_env_has_untrusted_expr(step, env_key)
}

step_env_has_untrusted_expr(step, env_key) {
	parsed_key := concat("", ["_parsed_expressions_", env_key])
	parsed := step.env[parsed_key][_]
	parsed.parse_ok == true
	cicd_lib.references_untrusted_context(parsed.raw)
}

containsPatterns(str, patterns) = matched {
    matched := {pattern |
        pattern := patterns[_]
        regex.match(pattern, str)
    }
}

check_trigger(doc, trigger) {
	doc.on == trigger
} else {
	doc.on[_] == trigger
} else {
	doc.on[key]
	key == trigger
}

get_step_name(step, s) := step_name {
	step_name := step.name
} else := step_name {
	step_name := sprintf("step-%d", [s])
}
