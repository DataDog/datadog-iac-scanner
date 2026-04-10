package Cx

import data.generic.common as common_lib

CxPolicy[result] {
	doc := input.document[i]
	check_trigger(doc, "pull_request_target")

	run := input.document[i].jobs[j].steps[k].run

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
		"documentId": input.document[i].id,
		"searchKey": sprintf("run={{%s}}", [run]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Run block does not contain dangerous input controlled by user.",
		"keyActualValue": "Run block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "run"],[]),
		"resourceType": "github_action",
		"resourceName": input.document[i].jobs[j].steps[k].name
	}
}

CxPolicy[result] {
	doc := input.document[i]
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
		"resourceName": doc.jobs[j].steps[k].name
	}
}

CxPolicy[result] {
	doc := input.document[i]
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
		"resourceName": doc.jobs[j].steps[k].name
	}
}

CxPolicy[result] {
	doc := input.document[i]
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
		"resourceName": doc.jobs[j].steps[k].name
	}
}

CxPolicy[result] {
	doc := input.document[i]
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
		"resourceName": doc.jobs[j].steps[k].name
	}
}

CxPolicy[result] {
	doc := input.document[i]
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
		"resourceName": doc.jobs[j].steps[k].name
	}
}

CxPolicy[result] {
	doc := input.document[i]
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
		"resourceName": doc.jobs[j].steps[k].name
	}
}

CxPolicy[result] {
	doc := input.document[i]
	check_trigger(doc, "pull_request")
	run := doc.jobs[j].steps[k].run

	patterns := [
		"github\\.head_ref",
		"github\\.event\\.pull_request\\.head.ref",
		"github\\.event\\.pull_request\\.head.label",
		"github\\.event\\.pull_request\\.head.repo\\..+",
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
		"resourceName": doc.jobs[j].steps[k].name
	}
}

CxPolicy[result] {
	doc := input.document[i]
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
		"resourceName": doc.jobs[j].steps[k].name
	}
}

CxPolicy[result] {
	doc := input.document[i]
	parsed_run := doc.jobs[j].steps[k]._parsed_expressions_run[_]

	walk(parsed_run, [_, node])

	node.type == "dereference_expression"

	matched = containsPatterns(node.value, ["^env\\."])
	count(matched) > 0

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("run={{%s}}", [parsed_run]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Run block does not contain dangerous input controlled by user.",
		"keyActualValue": "Run block contains dangerous input controlled by user.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "run"],[]),
		"resourceType": "github_action",
		"resourceName": doc.jobs[j].steps[k].name
	}
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
