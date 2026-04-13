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

	severity := get_severity(is_user_controllable)

	severity == "HIGH"

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.if", [j]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Use explicit equality checks or JSON array with contains() instead of space-separated string",
		"keyActualValue": sprintf("contains() condition can be bypassed if attacker controls the context value", []),
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

	severity == "HIGH"

	# Get step name if available
	step_name := object.get(step, "name", sprintf("step-%d", [s]))

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.steps[%d].if", [j, s]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Use explicit equality checks or JSON array with contains() instead of space-separated string",
		"keyActualValue": sprintf("Step '%s' contains() condition can be bypassed", [step_name]),
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", s, "if"], []),
		"resourceType": "github_action",
		"resourceName": step_name
	}
}

# Find vulnerable contains() calls in the AST
# Returns an object with first_arg and second_arg if vulnerable pattern found
find_vulnerable_contains(ast) = result {
	# Get all nodes from the AST (root and all descendants)
	walk(ast, [_, node])

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

	result := {
		"first_arg": first_arg,
		"second_arg": second_arg
	}
}

# Check if a node is a string literal
is_string_literal(node) {
	node.type == "string"
}

# Check if an AST node references a user-controllable context
check_user_controllable_in_ast(node) = true {
	# Get the full text of the node
	node_text := get_node_text(node)

	# Check against user-controllable contexts
	context := user_controllable_contexts[_]
	startswith(node_text, context)
} else = false {
	true
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
