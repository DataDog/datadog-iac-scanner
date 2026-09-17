package datadog

import rego.v1

DatadogPolicy contains result if {
	input.document[i].on.pull_request_target

	uses := input.document[i].jobs[j].steps[k].uses

	startswith(uses, "actions/github-script")

	script := input.document[i].jobs[j].steps[k]["with"].script

	patterns := [
		"github.head_ref",
		"github.event.pull_request.body",
		"github.event.pull_request.head.label",
		"github.event.pull_request.head.ref",
		"github.event.pull_request.head.repo.default_branch",
		"github.event.pull_request.head.repo.description",
		"github.event.pull_request.head.repo.homepage",
		"github.event.pull_request.title",
	]

	matched = containsPatterns(script, patterns)
	count(matched) > 0

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"resourceType": "github_action",
		"resourceName": object.get(input.document[i].jobs[j].steps[k], "name", sprintf("step-%d", [k])),
	}
}

DatadogPolicy contains result if {
	input.document[i].on.issues

	uses := input.document[i].jobs[j].steps[k].uses

	startswith(uses, "actions/github-script")

	script := input.document[i].jobs[j].steps[k]["with"].script

	patterns := [
		"github.event.issue.body",
		"github.event.issue.title",
	]

	matched = containsPatterns(script, patterns)
	count(matched) > 0

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"resourceType": "github_action",
		"resourceName": object.get(input.document[i].jobs[j].steps[k], "name", sprintf("step-%d", [k])),
	}
}

DatadogPolicy contains result if {
	input.document[i].on.issue_comment

	uses := input.document[i].jobs[j].steps[k].uses

	startswith(uses, "actions/github-script")

	script := input.document[i].jobs[j].steps[k]["with"].script

	patterns := [
		"github.event.comment.body",
		"github.event.issue.body",
		"github.event.issue.title",
	]

	matched = containsPatterns(script, patterns)
	count(matched) > 0

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"resourceType": "github_action",
		"resourceName": object.get(input.document[i].jobs[j].steps[k], "name", sprintf("step-%d", [k])),
	}
}

DatadogPolicy contains result if {
	input.document[i].on.discussion

	uses := input.document[i].jobs[j].steps[k].uses

	startswith(uses, "actions/github-script")

	script := input.document[i].jobs[j].steps[k]["with"].script

	patterns := [
		"github.event.discussion.body",
		"github.event.discussion.title",
	]

	matched = containsPatterns(script, patterns)
	count(matched) > 0

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"resourceType": "github_action",
		"resourceName": object.get(input.document[i].jobs[j].steps[k], "name", sprintf("step-%d", [k])),
	}
}

DatadogPolicy contains result if {
	input.document[i].on.discussion_comment

	uses := input.document[i].jobs[j].steps[k].uses

	startswith(uses, "actions/github-script")

	script := input.document[i].jobs[j].steps[k]["with"].script

	patterns := [
		"github.event.comment.body",
		"github.event.discussion.body",
		"github.event.discussion.title",
	]

	matched = containsPatterns(script, patterns)
	count(matched) > 0

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"resourceType": "github_action",
		"resourceName": object.get(input.document[i].jobs[j].steps[k], "name", sprintf("step-%d", [k])),
	}
}

DatadogPolicy contains result if {
	input.document[i].on.workflow_run

	uses := input.document[i].jobs[j].steps[k].uses

	startswith(uses, "actions/github-script")

	script := input.document[i].jobs[j].steps[k]["with"].script

	patterns := [
		"github.event.workflow.path",
		"github.event.workflow_run.head_branch",
		"github.event.workflow_run.head_commit.author.email",
		"github.event.workflow_run.head_commit.author.name",
		"github.event.workflow_run.head_commit.message",
		"github.event.workflow_run.head_repository.description",
	]

	matched = containsPatterns(script, patterns)
	count(matched) > 0

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"resourceType": "github_action",
		"resourceName": object.get(input.document[i].jobs[j].steps[k], "name", sprintf("step-%d", [k])),
	}
}

DatadogPolicy contains result if {
	input.document[i].on.author

	uses := input.document[i].jobs[j].steps[k].uses

	startswith(uses, "actions/github-script")

	script := input.document[i].jobs[j].steps[k]["with"].script

	patterns := [
		"github.*.authors.name",
		"github.*.authors.email",
	]

	matched = containsPatterns(script, patterns)
	count(matched) > 0

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("script={{%s}}", [script]),
		"resourceType": "github_action",
		"resourceName": object.get(input.document[i].jobs[j].steps[k], "name", sprintf("step-%d", [k])),
	}
}

containsPatterns(str, patterns) := matched if {
	matched := {pattern |
		pattern := patterns[_]
		regex.match(pattern, str)
	}
}
