package Cx

import data.generic.common as common_lib

# NOTE: This rule requires GitHub Actions expression parsing to be fully implemented.
#
# EXPRESSION PARSING REQUIREMENTS:
# 1. Extract all fenced expressions from workflow content (e.g., "${{ fromJSON(secrets.foo) }}")
# 2. Parse each expression using GitHub Actions expression syntax into an AST
# 3. Traverse the expression AST recursively to find function calls to fromJSON() where:
#    - The function name is "fromJSON" (case insensitive)
#    - At least one argument is a secrets context access (e.g., secrets.MY_SECRET)
# 4. For each expression type, recursively check:
#    - Expr::Call => If func == "fromJSON" and any arg is child_of("secrets"), flag it
#    - Expr::Index, Expr::Context, Expr::BinOp, Expr::UnOp => Recursively traverse
# 5. These patterns bypass GitHub's automatic secret redaction because the secret value
#    is transformed (JSON decoded) before being output, so GitHub can't recognize it
#
# EXAMPLES OF VULNERABLE PATTERNS:
# - fromJSON(secrets.MY_CONFIG)
# - fromjson(SECRETS.data)
# - fromJSON(secrets.foo).bar
# - fromJSON(secrets.foo).bar.baz
# - fromJSON(secrets.foo) && fromJSON(secrets.bar)
#
# SIMPLIFIED VERSION: This implementation uses string pattern matching to detect
# fromJSON(secrets.*) patterns. It will catch obvious cases but lacks the precision
# of full AST-based expression parsing.

# Detect fromJSON(secrets.*) patterns that bypass secret redaction
CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j]

	# Convert job to string for pattern matching
	# NOTE: Proper implementation would parse expressions and traverse AST
	job_str := sprintf("%v", [job])

	# Look for fromJSON with secrets context (case insensitive approximation)
	# This regex attempts to match: fromJSON(secrets.*) or fromjson(SECRETS.*)
	regex.match("(?i)fromjson\\s*\\(\\s*secrets\\.", job_str)

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s", [j]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Secrets should not be passed through fromJSON() or similar transformation functions",
		"keyActualValue": "Expression bypasses secret redaction by transforming secret value",
		"searchLine": common_lib.build_search_line(["jobs", j], []),
		"resourceType": "github_job",
		"resourceName": j
	}
}

# Also check at step level for more precise location
CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j]
	step := job.steps[s]

	# Convert step to string
	step_str := sprintf("%v", [step])

	# Look for fromJSON with secrets context
	regex.match("(?i)fromjson\\s*\\(\\s*secrets\\.", step_str)

	# Get step name if available, otherwise use index
	step_name := object.get(step, "name", sprintf("step-%d", [s]))

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.steps[%d]", [j, s]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Secrets should not be passed through fromJSON() or similar transformation functions",
		"keyActualValue": sprintf("Step '%s' bypasses secret redaction by transforming secret value", [step_name]),
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", s], []),
		"resourceType": "github_step",
		"resourceName": step_name
	}
}
