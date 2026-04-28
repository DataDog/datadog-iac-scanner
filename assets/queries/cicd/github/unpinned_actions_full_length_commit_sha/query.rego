package Cx

import data.generic.cicd as cicd_lib
import data.generic.common as common_lib

CxPolicy[result] {

	uses := input.document[i].jobs[j].steps[k].uses
	not isAllowed(uses)
	not isPinned(uses)
	not isRelative(uses)
	
	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("uses={{%s}}", [uses]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Action pinned to a full length commit SHA.",
		"keyActualValue": "Action is not pinned to a full length commit SHA.",
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "uses"],[]),
		"resourceType": "github_action",
		"resourceName": input.document[i].jobs[j].steps[k].name
	}
}

# Composite action: `uses` references under `runs.steps[*]` must also be SHA-pinned.
CxPolicy[result] {
	doc := input.document[i]
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
		"resourceName": object.get(step, "name", sprintf("step-%d", [k]))
	}
}


isAllowed(use){
	allowed := ["actions/"]
    startswith(use,allowed[i])
}

isPinned(use){
	regex.match("@[a-f0-9]{40}$", use)
}

isRelative(use){
	allowed := ["./"]
    startswith(use,allowed[i])
}

