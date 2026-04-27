package Cx

import data.generic.cicd as cicd_lib
import data.generic.common as common_lib
import data.generic.cicd as cicd_lib

CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"

	check_trigger(doc, "pull_request_target")

    uses := doc.jobs[j].steps[k].uses

    startswith(uses, "actions/github-script")
    
    script := doc.jobs[j].steps[k]["with"].script

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

	matched = containsPatterns(script, patterns)
	count(matched) > 0

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Script block does not contain dangerous input controlled by user.",
		"keyActualValue": "Script block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "with", "script"],[]),
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"

	check_trigger(doc, "issues")

	uses := doc.jobs[j].steps[k].uses

    startswith(uses, "actions/github-script")
    
    script := doc.jobs[j].steps[k]["with"].script

	patterns := [
    "github\\.event\\.issue\\.body",
	"github\\.event\\.issue\\.title"
	]

	matched = containsPatterns(script, patterns)
	count(matched) > 0

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Script block does not contain dangerous input controlled by user.",
		"keyActualValue": "Script block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "with", "script"],[]),
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"

	check_trigger(doc, "issue_comment")
	
	uses := doc.jobs[j].steps[k].uses

    startswith(uses, "actions/github-script")
    
    script := doc.jobs[j].steps[k]["with"].script

	patterns := [
    "github\\.event\\.comment\\.body",
	"github\\.event\\.issue\\.body",
	"github\\.event\\.issue\\.title"
	]

	matched = containsPatterns(script, patterns)
	count(matched) > 0

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Script block does not contain dangerous input controlled by user.",
		"keyActualValue": "Script block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "with","script"],[]),
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"

	check_trigger(doc, "discussion")
	
	uses := doc.jobs[j].steps[k].uses

    startswith(uses, "actions/github-script")
    
    script := doc.jobs[j].steps[k]["with"].script

	patterns := [
    "github\\.event\\.discussion\\.body",
	"github\\.event\\.discussion\\.title"
	]

	matched = containsPatterns(script, patterns)
	count(matched) > 0

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Script block does not contain dangerous input controlled by user.",
		"keyActualValue": "Script block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "with", "script"],[]),
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"

	check_trigger(doc, "discussion_comment")
	
	uses := doc.jobs[j].steps[k].uses

    startswith(uses, "actions/github-script")
    
    script := doc.jobs[j].steps[k]["with"].script

	patterns := [
    "github\\.event\\.comment\\.body",
	"github\\.event\\.discussion\\.body",
	"github\\.event\\.discussion\\.title"
	]

	matched = containsPatterns(script, patterns)
	count(matched) > 0

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Script block does not contain dangerous input controlled by user.",
		"keyActualValue": "Script block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "with", "script"],[]),
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"

	check_trigger(doc, "workflow_run")
	
	uses := doc.jobs[j].steps[k].uses

    startswith(uses, "actions/github-script")
    
    script := doc.jobs[j].steps[k]["with"].script

	patterns := [
    "github\\.event\\.workflow\\.path",
	"github\\.event\\.workflow_run\\.head_branch",
	"github\\.event\\.workflow_run\\.head_commit\\.author\\.email",
	"github\\.event\\.workflow_run\\.head_commit\\.author\\.name",
	"github\\.event\\.workflow_run\\.head_commit\\.message",
	"github\\.event\\.workflow_run\\.head_repository\\.description"
	]

	matched = containsPatterns(script, patterns)
	count(matched) > 0

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Script block does not contain dangerous input controlled by user.",
		"keyActualValue": "Script block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "with", "script"],[]),
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"

	check_trigger(doc, "author")
	
	uses := doc.jobs[j].steps[k].uses

    startswith(uses, "actions/github-script")
    
    script := doc.jobs[j].steps[k]["with"].script

	patterns := [
    "github\\..*\\.authors\\.name",
	"github\\..*\\.authors\\.email"
	]

	matched = containsPatterns(script, patterns)
	count(matched) > 0

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Script block does not contain dangerous input controlled by user.",
		"keyActualValue": "Script block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "with", "script"],[]),
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	check_trigger(doc, "pull_request")
	step := doc.jobs[j].steps[k]

	uses := step.uses
    startswith(uses, "actions/github-script")
    script := step["with"].script

	patterns := [
		"github\\.head_ref",
		"github\\.event\\.pull_request\\.head\\.ref",
		"github\\.event\\.pull_request\\.head\\.label",
		"github\\.event\\.pull_request\\.head\\.repo\\..+",
		"github\\.event\\.pull_request\\.title",
		"github\\.event\\.pull_request\\.body",
	]

	matched = containsPatterns(script, patterns)
	count(matched) > 0

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Script block does not contain dangerous input controlled by user.",
		"keyActualValue": "Script block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "with", "script"],[]),
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	check_trigger(doc, "workflow_dispatch")
	step := doc.jobs[j].steps[k]

	uses := step.uses
    startswith(uses, "actions/github-script")
    script := step["with"].script

	patterns := [
		"github\\.event\\.inputs\\..+"
	]

	matched = containsPatterns(script, patterns)
	count(matched) > 0

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Script block does not contain dangerous input controlled by user.",
		"keyActualValue": "Script block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "with", "script"],[]),
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

	step := doc.runs.steps[k]
	uses := step.uses
	startswith(uses, "actions/github-script")
	script := step["with"].script

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

	matched := containsPatterns(script, patterns)
	count(matched) > 0

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Script block does not contain dangerous input controlled by user.",
		"keyActualValue": "Script block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["runs", "steps", k, "with", "script"], []),
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.runs.steps[k], k)
	}
}

# Composite action: ${{ inputs.* }} interpolated into an actions/github-script body.
# Driven by the parsed GitHub Actions expression AST so that nested contexts
# such as ${{ github.event.inputs.* }} are handled by the broader rule above
# and do not double-fire here through substring matching of `inputs.`.
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	
	cicd_lib.is_composite_action(doc)

	step := doc.runs.steps[k]
	uses := step.uses
	startswith(uses, "actions/github-script")
	script := step["with"].script

	parsed_script := step["with"]._parsed_expressions_script[_]

	walk(parsed_script, [_, node])
	cicd_lib.is_bare_inputs_dereference(node)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Script block does not directly interpolate composite action inputs into the script.",
		"keyActualValue": "Script block directly interpolates a composite action input into actions/github-script, which can lead to code injection if the input is attacker-controlled.",
		"searchLine": common_lib.build_search_line(["runs", "steps", k, "with", "script"], []),
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.runs.steps[k], k)
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


containsPatterns(str, patterns) = matched {
    matched := {pattern |
        pattern := patterns[_]
        regex.match(pattern, str)
    }
}


get_step_name(step, s) := step_name {
	step_name := step.name
} else := step_name {
	step_name := sprintf("step-%d", [s])
}
