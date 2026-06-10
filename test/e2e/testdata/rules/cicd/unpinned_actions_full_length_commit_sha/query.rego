package datadog

import rego.v1

import data.generic.cicd as cicd_lib
import data.generic.common as common_lib

DatadogPolicy contains result if {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"

	uses := doc.jobs[j].steps[k].uses
	not isAllowed(uses)
	not isPinned(uses)
	not isRelative(uses)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("uses={{%s}}", [uses]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Action pinned to a full length commit SHA.",
		"keyActualValue": "Action is not pinned to a full length commit SHA.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "uses"], []),
		"resourceType": "github_action",
		"resourceName": get_object_name(doc.jobs[j].steps[k], "step", k),
	}
}

DatadogPolicy contains result if {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"

	uses := doc.jobs[j].uses
	not isAllowed(uses)
	not isPinned(uses)
	not isRelative(uses)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("uses={{%s}}", [uses]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Action pinned to a full length commit SHA.",
		"keyActualValue": "Action is not pinned to a full length commit SHA.",
		"searchLine": common_lib.build_search_line(["jobs", j, "uses"], []),
		"resourceType": "github_action",
		"resourceName": get_object_name(doc.jobs[j], "job", j),
	}
}

# Composite action: `uses` references under `runs.steps[*]` must also be SHA-pinned.
DatadogPolicy contains result if {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"

	cicd_lib.is_composite_action(doc)

	step := doc.runs.steps[k]
	uses := step.uses
	not isAllowed(uses)
	not isPinned(uses)
	not isRelative(uses)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("uses={{%s}}", [uses]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Action pinned to a full length commit SHA.",
		"keyActualValue": "Action is not pinned to a full length commit SHA.",
		"searchLine": common_lib.build_search_line(["runs", "steps", k, "uses"], []),
		"resourceType": "github_action",
		"resourceName": object.get(step, "name", sprintf("step-%d", [k])),
	}
}

isAllowed(use) if {
	allowed := ["actions/"]
	startswith(use, allowed[i])
}

isPinned(use) if {
	regex.match("@[a-f0-9]{40}$", use)
}

isRelative(use) if {
	allowed := ["./"]
	startswith(use, allowed[i])
}

get_object_name(object, object_title, index) := object_name if {
	object_name := object.name
} else := object_name if {
	object_name := sprintf("%s-%v", [object_title, index])
}
