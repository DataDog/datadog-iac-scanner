package Cx

import data.generic.common as common_lib
import future.keywords.in

CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j]
	step := job.steps[s]

	# Get the uses field
	uses := step.uses
	is_string(uses)

	# Parse and check for obfuscation
	obfuscation_issues := detect_obfuscation(uses)
	count(obfuscation_issues) > 0

	issue_description := concat(", ", obfuscation_issues)
	doc_name := object.get(doc, "name", "document")
	result := {
		"documentId": doc.id,
		"resourceType": "step",
		"resourceName": sprintf("step %d in job '%s'", [s, j]),
		"searchKey": sprintf("jobs.%s.steps", [doc_name, j]),
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", s, "uses"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'uses' should not contain obfuscated path components", []),
		"keyActualValue": sprintf("'uses' contains obfuscated path components: %s", [issue_description]),
	}
}

# Detect obfuscation patterns in a uses string
detect_obfuscation(uses) := issues {
	# Exclude Docker actions
	not startswith(uses, "docker://")

	# Exclude local actions (legitimate use of ./ prefix)
	not is_local_action(uses)

	# Check if it's a repository action (owner/repo format)
	is_repository_action(uses)

	# Extract the path component (between owner/repo/ and @ref)
	path_component := get_path_component(uses)

	# Find all obfuscation issues in the path
	issues := [issue |
		some segment in path_component
		issue := check_segment_obfuscation(segment)
		issue != "" 
	]
}

# Check if it's a local action (starts with ./ or ../)
is_local_action(uses) {
	startswith(uses, "./")
}

is_local_action(uses) {
	startswith(uses, "../")
}

# Check if it's a repository action (owner/repo format)
is_repository_action(uses) {
	# Must contain @ symbol for versioning
	contains(uses, "@")

	# Must contain at least two slashes (owner/repo/path or owner/repo@ref)
	parts := split(uses, "/")
	count(parts) >= 2

	# First part should not be . or ..
	parts[0] != "."
	parts[0] != ".."
}

# Extract path component from uses string
# For "owner/repo/path/to/action@ref", extract "path/to/action"
# For "owner/repo@ref", return empty string
get_path_component(uses) := path {
	# Split by @ to separate ref
	at_parts := split(uses, "@")
	before_at := at_parts[0]

	# Split by / to get parts
	slash_parts := split(before_at, "/")

	# If only owner/repo (2 parts), no path component
	count(slash_parts) == 2
	path := []
}

get_path_component(uses) := path_parts {
	# Split by @ to separate ref
	at_parts := split(uses, "@")
	before_at := at_parts[0]

	# Split by / to get parts
	slash_parts := split(before_at, "/")

	# If more than owner/repo, extract path (everything after owner/repo)
	count(slash_parts) > 2

	# Join all parts after owner/repo
	path_parts := array.slice(slash_parts, 2, count(slash_parts))
}

# Check individual path segment for obfuscation
check_segment_obfuscation(segment) := "actions reference contains empty component" {
	segment == ""
}

check_segment_obfuscation(segment) := "actions reference contains '.'" {
	segment == "."
}

check_segment_obfuscation(segment) := "actions reference contains '..'" {
	segment == ".."
}

check_segment_obfuscation(segment) := "" {
	# No obfuscation detected
	segment != ""
	segment != "."
	segment != ".."
}
