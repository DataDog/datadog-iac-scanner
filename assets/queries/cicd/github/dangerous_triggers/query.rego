package Cx

import data.generic.common as common_lib

# Check for pull_request_target trigger
CxPolicy[result] {
	doc := input.document[i]

	# Check if pull_request_target is in the triggers
	doc.on == "pull_request_target"
	doc_name := object.get(doc, "name", sprintf("document", []))

	result := {
		"documentId": doc.id,
		"searchKey": "on.pull_request_target",
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Workflow should not use pull_request_target trigger",
		"keyActualValue": "Workflow uses pull_request_target trigger which is almost always used insecurely",
		"searchLine": common_lib.build_search_line(["on", "pull_request_target"], []),
		"resourceType": "github_action",
		"resourceName": doc_name
	}
}

# Check for pull_request_target in array format
CxPolicy[result] {
	doc := input.document[i]

	# Check if on is an array and contains pull_request_target
	is_array(doc.on)
	doc.on[_] == "pull_request_target"

	doc_name := object.get(doc, "name", sprintf("document", []))
	result := {
		"documentId": doc.id,
		"searchKey": "on",
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Workflow should not use pull_request_target trigger",
		"keyActualValue": "Workflow uses pull_request_target trigger which is almost always used insecurely",
		"searchLine": common_lib.build_search_line(["on"], []),
		"resourceType": "github_action",
		"resourceName": doc_name
	}
}

# Check for pull_request_target in object format
CxPolicy[result] {
	doc := input.document[i]

	# Check if on is an object and contains pull_request_target
	is_object(doc.on[key])
	key == "pull_request_target"

	doc_name := object.get(doc, "name", sprintf("document", []))
	result := {
		"documentId": doc.id,
		"searchKey": "on",
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Workflow should not use pull_request_target trigger",
		"keyActualValue": "Workflow uses pull_request_target trigger which is almost always used insecurely",
		"searchLine": common_lib.build_search_line(["on"], []),
		"resourceType": "github_action",
		"resourceName": doc_name
	}
}

# Check for workflow_run trigger
CxPolicy[result] {
	doc := input.document[i]

	# Check if workflow_run is in the triggers
	doc.on == "workflow_run"

	doc_name := object.get(doc, "name", sprintf("document", []))
	result := {
		"documentId": doc.id,
		"searchKey": "on.workflow_run",
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Workflow should not use workflow_run trigger",
		"keyActualValue": "Workflow uses workflow_run trigger which is almost always used insecurely",
		"searchLine": common_lib.build_search_line(["on", "workflow_run"], []),
		"resourceType": "github_action",
		"resourceName": doc_name
	}
}

# Check for workflow_run in array format
CxPolicy[result] {
	doc := input.document[i]

	# Check if on is an array and contains workflow_run
	is_array(doc.on)
	doc.on[_] == "workflow_run"

	doc_name := object.get(doc, "name", sprintf("document", []))
	result := {
		"documentId": doc.id,
		"searchKey": "on",
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Workflow should not use workflow_run trigger",
		"keyActualValue": "Workflow uses workflow_run trigger which is almost always used insecurely",
		"searchLine": common_lib.build_search_line(["on"], []),
		"resourceType": "github_action",
		"resourceName": doc_name
	}
}

# Check for workflow_run in object format
CxPolicy[result] {
	doc := input.document[i]

	# Check if on is an object and contains workflow_run
	is_object(doc.on[name])
	name == "workflow_run"

	doc_name := object.get(doc, "name", sprintf("document", []))
	result := {
		"documentId": doc.id,
		"searchKey": "on",
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Workflow should not use workflow_run trigger",
		"keyActualValue": "Workflow uses workflow_run trigger which is almost always used insecurely",
		"searchLine": common_lib.build_search_line(["on"], []),
		"resourceType": "github_action",
		"resourceName": doc_name
	}
}
