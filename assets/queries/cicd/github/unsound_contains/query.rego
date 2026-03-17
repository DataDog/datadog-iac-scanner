package Cx

import data.generic.common as common_lib

# User-controllable contexts that make this HIGH severity
user_controllable_contexts := {
	"github.actor",
	"github.triggering_actor",
	"github.base_ref",
	"github.head_ref",
	"github.ref",
	"github.ref_name",
	"github.sha",
	"env.",
	"inputs."
}

# Check for unsafe contains() patterns in job conditions
CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j]

	# Get parsed expressions from the if condition
	parsed_exprs := job["_parsed_expressions_if"]
	parsed_expr := parsed_exprs[_]

	# Only process successfully parsed expressions
	parsed_expr.parse_ok == true

	# Find vulnerable contains() calls in the AST
	vulnerable_call := find_vulnerable_contains(parsed_expr.ast)

	# Determine severity based on context
	is_user_controllable := check_user_controllable_in_ast(vulnerable_call.second_arg)
	# Severity is not actually controllable through IaC Scanning
	# Option 1: Only keep rule for HIGH Severity
	# Option 2: Keep HIGH Severity for all cases
	# Option 3: Add mechanism to adapt Severity
	severity := get_severity(is_user_controllable)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.if", [j]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Use explicit equality checks or JSON array with contains() instead of space-separated string",
		"keyActualValue": sprintf("contains() condition can be bypassed if attacker controls the context value (%s severity)", [severity]),
		"searchLine": common_lib.build_search_line(["jobs", j, "if"], []),
		"resourceType": "github_action",
		"resourceName": j
	}
}

# Check for unsafe contains() patterns in step conditions
CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j]
	step := job.steps[s]

	# Get parsed expressions from the if condition
	parsed_exprs := step["_parsed_expressions_if"]
	parsed_expr := parsed_exprs[_]

	# Only process successfully parsed expressions
	parsed_expr.parse_ok == true

	# Find vulnerable contains() calls in the AST
	vulnerable_call := find_vulnerable_contains(parsed_expr.ast)

	# Determine severity based on context
	is_user_controllable := check_user_controllable_in_ast(vulnerable_call.second_arg)
	severity := get_severity(is_user_controllable)

	# Get step name if available
	step_name := object.get(step, "name", sprintf("step-%d", [s]))

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.steps[%d].if", [j, s]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Use explicit equality checks or JSON array with contains() instead of space-separated string",
		"keyActualValue": sprintf("Step '%s' contains() condition can be bypassed (%s severity)", [step_name, severity]),
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", s, "if"], []),
		"resourceType": "github_action",
		"resourceName": step_name
	}
}

# Find vulnerable contains() calls in the AST
# Returns an object with first_arg and second_arg if vulnerable pattern found
find_vulnerable_contains(ast) = result {
	# Get all nodes from the AST (root and all descendants)
	all_nodes := get_all_nodes(ast)
	node := all_nodes[_]

	# Check if this is a function_call node with function "contains"
	node.type == "function_call"

	# Get the function name
	func_child := node.children[_]
	func_child.type == "identifier"
	func_child.value == "contains"

	# Get the argument_list
	arg_list := node.children[_]
	arg_list.type == "argument_list"

	# Extract the two arguments
	args := [arg | arg := arg_list.children[_]; arg.type != ","]
	count(args) == 2

	first_arg := args[0]
	second_arg := args[1]

	# First argument must be a string literal
	is_string_literal(first_arg)

	# First argument must contain spaces or delimiters (indicating multiple values)
	string_value := get_string_value(first_arg)
	has_delimiter(string_value)

	result := {
		"first_arg": first_arg,
		"second_arg": second_arg
	}
}

# Collect all nodes from the AST using iteration
# Rego cannot use recursive function calls, thus the pseudo-iteration
get_all_nodes(node) = nodes {
	# Start with the node itself
	nodes := {node} | get_children_nodes(node)
}

# Get all descendant nodes iteratively
get_children_nodes(node) = nodes {
	# Collect immediate children
	children := {child | child := node.children[_]}

	# Collect grandchildren and deeper
	grandchildren := {grandchild |
		child := node.children[_]
		grandchild := child.children[_]
	}

	# Collect great-grandchildren
	great_grandchildren := {ggchild |
		child := node.children[_]
		grandchild := child.children[_]
		ggchild := grandchild.children[_]
	}

	# Collect great-great-grandchildren (should be deep enough for most expressions)
	gggrandchildren := {gggchild |
		child := node.children[_]
		grandchild := child.children[_]
		ggchild := grandchild.children[_]
		gggchild := ggchild.children[_]
	}

	nodes := children | grandchildren | great_grandchildren | gggrandchildren
}

# Check if a node is a string literal
is_string_literal(node) {
	node.type == "string"
}

# Get the string value from a string literal node
get_string_value(node) = value {
	# String nodes have a child of type "string_fragment" that contains the actual text
	string_fragment := node.children[_]
	string_fragment.type == "string_fragment"
	value := string_fragment.value
}

# Check if string contains delimiters (spaces, pipes, etc.)
has_delimiter(str) {
	# Check for space
	contains(str, " ")
}

has_delimiter(str) {
	# Check for pipe
	contains(str, "|")
}

# Check if an AST node references a user-controllable context
check_user_controllable_in_ast(node) {
	# Get the full text of the node
	node_text := get_node_text(node)

	# Check against user-controllable contexts
	context := user_controllable_contexts[_]
	startswith(node_text, context)
}

# Get the text representation of a node
get_node_text(node) = node.value {
	node.value != ""
}

get_node_text(node) = text {
	# If node doesn't have a value, construct from children
	node.value == ""
	child_texts := [child.value | child := node.children[_]; child.value != ""]
	text := concat(".", child_texts)
}

# Helper: Determine severity based on whether context is user-controllable
get_severity(is_user_controllable) = "HIGH" {
	is_user_controllable
}

get_severity(is_user_controllable) = "LOW" {
	not is_user_controllable
}
