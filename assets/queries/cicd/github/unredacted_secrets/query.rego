package Cx

import data.generic.common as common_lib
import data.generic.cicd as cicd_lib

# Check for fromJSON(secrets.*) patterns in all parsed expressions within a step
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	job := doc.jobs[j]
	step := job.steps[s]

	# Get all parsed expressions in the step
	# The parser adds _parsed_expressions_* for each field containing expressions
	parsed_exprs := get_all_parsed_expressions(step)
	parsed_expr := parsed_exprs[_]

	# Only process successfully parsed expressions
	parsed_expr.parse_ok == true

	# Check if this expression contains fromJSON(secrets.*)
	has_vulnerable_pattern(parsed_expr.ast)

	# Get step name if available, otherwise use index
	step_name := object.get(step, "name", sprintf("step-%d", [s]))

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.steps[%d]", [j, s]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Secrets should not be passed through fromJSON() or similar transformation functions",
		"keyActualValue": sprintf("Step '%s' bypasses secret redaction by transforming secret value", [step_name]),
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", s], []),
		"resourceType": "github_action",
		"resourceName": step_name
	}
}

# Check for fromJSON(secrets.*) patterns in job-level fields
CxPolicy[result] {
	doc := input.document[i]
	cicd_lib.check_provider(doc) == "github"
	job := doc.jobs[j]

	# Get all parsed expressions in the job
	parsed_exprs := get_all_parsed_expressions(job)
	parsed_expr := parsed_exprs[_]

	# Only process successfully parsed expressions
	parsed_expr.parse_ok == true

	# Check if this expression contains fromJSON(secrets.*)
	has_vulnerable_pattern(parsed_expr.ast)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s", [j]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Secrets should not be passed through fromJSON() or similar transformation functions",
		"keyActualValue": "Expression bypasses secret redaction by transforming secret value",
		"searchLine": common_lib.build_search_line(["jobs", j], []),
		"resourceType": "github_action",
		"resourceName": j
	}
}

# Get all parsed expressions from a map (step or job), including nested maps
get_all_parsed_expressions(obj) = exprs {
	# Collect expressions from top level
	top_level_exprs := [expr |
		key := object.keys(obj)[_]
		startswith(key, "_parsed_expressions_")
		expr := obj[key][_]
	]

	# Collect expressions from nested maps (env, with, etc.)
	nested_exprs := [expr |
		key := object.keys(obj)[_]
		not startswith(key, "_parsed_expressions_")
		is_object(obj[key])
		nested_key := object.keys(obj[key])[_]
		startswith(nested_key, "_parsed_expressions_")
		expr := obj[key][nested_key][_]
	]

	# Combine both
	exprs := array.concat(top_level_exprs, nested_exprs)
}

# Check if the AST contains fromJSON(secrets.*) pattern
has_vulnerable_pattern(ast) {
	# Get all nodes from the AST
	all_nodes := get_all_nodes(ast)
	node := all_nodes[_]

	# Check if this is a fromJSON function call
	node.type == "function_call"

	# Get the function name (case insensitive check)
	func_name := get_function_name(node)
	lower(func_name) == "fromjson"

	# Check if any argument contains a reference to secrets
	arg_list := node.children[_]
	arg_list.type == "argument_list"

	# Check if any argument references secrets
	contains_secrets_reference(arg_list)
}

# Get the function name from a function_call node
get_function_name(node) = name {
	# The first child should be the identifier
	child := node.children[_]
	child.type == "identifier"
	name := child.value
}

# Check if an argument list contains a reference to secrets
contains_secrets_reference(arg_list) {
	# Get all nodes in the argument list
	arg_nodes := get_all_nodes(arg_list)
	node := arg_nodes[_]

	# Check if this node is a dereference_expression that starts with "secrets"
	node.type == "dereference_expression"
	contains(lower(node.value), "secrets")
}

# Alternative: check for identifier "secrets"
contains_secrets_reference(arg_list) {
	arg_nodes := get_all_nodes(arg_list)
	node := arg_nodes[_]
	node.type == "identifier"
	lower(node.value) == "secrets"
}

# Collect all nodes from the AST using iteration
# Rego cannot use recursive function calls, thus the pseudo-iteration
get_all_nodes(node) = nodes {
	# Start with the node itself
	nodes := {node} | get_children_nodes(node)
}

# Get all descendant nodes iteratively
# Rego does not support recursion, thus this pseudo-iteration
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
