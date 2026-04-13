package Cx

import data.generic.common as common_lib

CxPolicy[result] {
	doc := input.document[i]

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

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Script block does not contain dangerous input controlled by user.",
		"keyActualValue": "Script block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "with", "script"],[]),
		"searchValue": matched[m],
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

CxPolicy[result] {
	doc := input.document[i]

	check_trigger(doc, "issues")

	uses := doc.jobs[j].steps[k].uses

    startswith(uses, "actions/github-script")
    
    script := doc.jobs[j].steps[k]["with"].script

	patterns := [
    "github\\.event\\.issue\\.body",
	"github\\.event\\.issue\\.title"
	]

	matched = containsPatterns(script, patterns)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Script block does not contain dangerous input controlled by user.",
		"keyActualValue": "Script block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "with", "script"],[]),
		"searchValue": matched[m],
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

CxPolicy[result] {
	doc := input.document[i]

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

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Script block does not contain dangerous input controlled by user.",
		"keyActualValue": "Script block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "with","script"],[]),
		"searchValue": matched[m],
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

CxPolicy[result] {
	doc := input.document[i]

	check_trigger(doc, "discussion")
	
	uses := doc.jobs[j].steps[k].uses

    startswith(uses, "actions/github-script")
    
    script := doc.jobs[j].steps[k]["with"].script

	patterns := [
    "github\\.event\\.discussion\\.body",
	"github\\.event\\.discussion\\.title"
	]

	matched = containsPatterns(script, patterns)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Script block does not contain dangerous input controlled by user.",
		"keyActualValue": "Script block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "with", "script"],[]),
		"searchValue": matched[m],
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

CxPolicy[result] {
	doc := input.document[i]

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

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Script block does not contain dangerous input controlled by user.",
		"keyActualValue": "Script block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "with", "script"],[]),
		"searchValue": matched[m],
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

CxPolicy[result] {
	doc := input.document[i]

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

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Script block does not contain dangerous input controlled by user.",
		"keyActualValue": "Script block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "with", "script"],[]),
		"searchValue": matched[m],
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

CxPolicy[result] {
	doc := input.document[i]

	check_trigger(doc, "author")
	
	uses := doc.jobs[j].steps[k].uses

    startswith(uses, "actions/github-script")
    
    script := doc.jobs[j].steps[k]["with"].script

	patterns := [
    "github\\..*\\.authors\\.name",
	"github\\..*\\.authors\\.email"
	]

	matched = containsPatterns(script, patterns)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Script block does not contain dangerous input controlled by user.",
		"keyActualValue": "Script block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "with", "script"],[]),
		"searchValue": matched[m],
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

CxPolicy[result] {
	doc := input.document[i]
	check_trigger(doc, "pull_request")
	step := doc.jobs[j].steps[k]

	uses := step.uses
    startswith(uses, "actions/github-script")
    script := step["with"].script

	patterns := [
		"github\\.head_ref",
		"github\\.event\\.pull_request\\.head.ref",
		"github\\.event\\.pull_request\\.head.label",
		"github\\.event\\.pull_request\\.head.repo\\..+",
		"github\\.event\\.pull_request\\.title",
		"github\\.event\\.pull_request\\.body",
	]

	matched = containsPatterns(script, patterns)
	count(matched) > 0

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "script block does not contain dangerous input controlled by user.",
		"keyActualValue": "script block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "script"],[]),
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
	}
}

CxPolicy[result] {
	doc := input.document[i]
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
		"keyExpectedValue": "script block does not contain dangerous input controlled by user.",
		"keyActualValue": "script block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "script"],[]),
		"resourceType": "github_action",
		"resourceName": get_step_name(doc.jobs[j].steps[k], k)
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
