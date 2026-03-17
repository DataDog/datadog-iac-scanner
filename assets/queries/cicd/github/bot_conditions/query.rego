package Cx

import data.generic.common as common_lib
import future.keywords.in

# Known bot actor IDs that can be checked
bot_actor_ids := {
	"29110",    # dependabot[bot]'s integration ID
	"49699333", # dependabot[bot]
	"27856297", # dependabot-preview[bot]
	"29139614", # renovate[bot]
}

# Spoofable actor name contexts
spoofable_actor_name_contexts := {
	"github.actor",
	"github.triggering_actor",
	"github.event.pull_request.sender.login",
}

# Spoofable actor ID contexts
spoofable_actor_id_contexts := {
	"github.actor_id",
	"github.event.pull_request.sender.id",
}

# All spoofable contexts (case-insensitive matching will be done)
all_spoofable_contexts := spoofable_actor_name_contexts | spoofable_actor_id_contexts

# Check if a string is a spoofable actor name context (case-insensitive)
is_spoofable_name_context(ctx) {
	lower_ctx := lower(ctx)
	some pattern in spoofable_actor_name_contexts
	lower(pattern) == lower_ctx
}

# Check if a string is a spoofable actor ID context (case-insensitive)
is_spoofable_id_context(ctx) {
	lower_ctx := lower(ctx)
	some pattern in spoofable_actor_id_contexts
	lower(pattern) == lower_ctx
}

# Check if a value looks like a bot name (ends with [bot])
is_bot_name(value) {
	endswith(value, "[bot]")
}

# Check if a value is a known bot actor ID
is_bot_id(value) {
	bot_actor_ids[value]
}

# Parse and check for bot conditions in an if expression
# Returns: {is_vulnerable: bool, context: string}
check_bot_condition_in_expression(expr) = has_bot_check {
	# Remove ${{ }} wrapper if present
	cleaned := trim_space(trim_prefix(trim_suffix(trim_space(expr), "}}"), "${{"))

	# Skip if entire expression is negated with ! operator
	not startswith(cleaned, "!")

	# Check for OR with bot condition (dominating)
	contains(cleaned, "||")
	has_bot_check := check_or_expression(cleaned)
} else = has_bot_check {
	# Remove ${{ }} wrapper if present
	cleaned := trim_space(trim_prefix(trim_suffix(trim_space(expr), "}}"), "${{"))

	# Skip if entire expression is negated with ! operator
	not startswith(cleaned, "!")

	# Check for AND with bot condition (non-dominating)
	contains(cleaned, "&&")
	has_bot_check := check_and_expression(cleaned)
} else = has_bot_check {
	# Remove ${{ }} wrapper if present
	cleaned := trim_space(trim_prefix(trim_suffix(trim_space(expr), "}}"), "${{"))

	# Skip if entire expression is negated with ! operator
	not startswith(cleaned, "!")

	# Simple equality check without logical operators (dominating)
	not contains(cleaned, "||")
	not contains(cleaned, "&&")
	has_bot_check := check_equality_expression(cleaned)
} else = {"is_vulnerable": false, "context": ""}

# Check OR expression parts for bot conditions
check_or_expression(expr) = result {
	parts := split(expr, "||")
	vulnerables = [parts[i] | bot_check := check_equality_expression(trim_space(parts[i])); bot_check.is_vulnerable]
	count(vulnerables) > 0
	string = concat(" || ", vulnerables)
	result := {"is_vulnerable": true, "context": string}
} else = {"is_vulnerable": false, "context": ""}

# Check AND expression parts for bot conditions
check_and_expression(expr) = result {
	# First check if this is a secure pattern (name check AND id check for same actor)
	is_secure_and_pattern(expr)
	result := {"is_vulnerable": false, "context": ""}
} else = result {
	# Not a secure pattern, check if any part has bot conditions
	parts := split(expr, "&&")
	vulnerable_parts = [parts[i] |
		bot_check := check_equality_expression(trim_space(parts[i]));
		bot_check.is_vulnerable
	]
	count(vulnerable_parts) > 0
	string = concat(" && ", vulnerable_parts)
	result := {"is_vulnerable": true, "context": string}
} else = {"is_vulnerable": false, "context": ""}

# Check if an AND expression is a secure pattern (name + ID verification)
is_secure_and_pattern(expr) {
	parts := split(expr, "&&")
	count(parts) >= 2

	# Check if we have both name and ID checks
	name_checks = [i |
		part := trim_space(parts[i])
		check := check_equality_expression(part)
		check.is_vulnerable
		context := extract_context_from_check(part)
		is_spoofable_name_context(context)
	]

	id_checks = [i |
		part := trim_space(parts[i])
		check := check_equality_expression(part)
		check.is_vulnerable
		context := extract_context_from_check(part)
		is_spoofable_id_context(context)
	]

	# Must have at least one name check and one ID check
	count(name_checks) > 0
	count(id_checks) > 0

	# Verify they're for related actor contexts (e.g., both github.actor*)
	has_matching_actor_contexts(parts, name_checks, id_checks)
}

# Helper to extract context from a check expression
extract_context_from_check(expr) = context {
	contains(expr, "==")
	not contains(expr, "!=")
	parts := split(expr, "==")
	count(parts) == 2

	left := trim_space(parts[0])
	right := trim_space(parts[1])

	# Try left side as context first
	left_context := extract_context_path(left)
	is_spoofable_name_context(left_context)
	context := left_context
} else = context {
	contains(expr, "==")
	not contains(expr, "!=")
	parts := split(expr, "==")
	count(parts) == 2

	left := trim_space(parts[0])
	right := trim_space(parts[1])

	# Try left side as context first
	left_context := extract_context_path(left)
	is_spoofable_id_context(left_context)
	context := left_context
} else = context {
	contains(expr, "==")
	not contains(expr, "!=")
	parts := split(expr, "==")
	count(parts) == 2

	left := trim_space(parts[0])
	right := trim_space(parts[1])

	# Try right side as context
	right_context := extract_context_path(right)
	context := right_context
}

# Check if name and ID checks refer to the same actor
has_matching_actor_contexts(parts, name_checks, id_checks) {
	# Get contexts from name and ID checks
	name_idx := name_checks[_]
	id_idx := id_checks[_]

	name_context := extract_context_from_check(trim_space(parts[name_idx]))
	id_context := extract_context_from_check(trim_space(parts[id_idx]))

	# Check if they're for the same actor type
	# github.actor pairs with github.actor_id
	# github.triggering_actor pairs with github.actor_id
	# github.event.pull_request.sender.login pairs with github.event.pull_request.sender.id
	contexts_match(name_context, id_context)
}

# Determine if two contexts are for the same actor
contexts_match(name_ctx, id_ctx) {
	# Normalize contexts
	lower_name := lower(name_ctx)
	lower_id := lower(id_ctx)

	# github.actor with github.actor_id
	lower_name == "github.actor"
	lower_id == "github.actor_id"
} else {
	# Normalize contexts
	lower_name := lower(name_ctx)
	lower_id := lower(id_ctx)

	# github.triggering_actor with github.actor_id
	lower_name == "github.triggering_actor"
	lower_id == "github.actor_id"
} else {
	# Normalize contexts
	lower_name := lower(name_ctx)
	lower_id := lower(id_ctx)

	# github.event.pull_request.sender.login with github.event.pull_request.sender.id
	lower_name == "github.event.pull_request.sender.login"
	lower_id == "github.event.pull_request.sender.id"
}

# Check a single equality expression for bot conditions
check_equality_expression(expr) = result {
	contains(expr, "==")
	not contains(expr, "!=")  # Exclude != operator
	parts := split(expr, "==")
	count(parts) == 2

	left := trim_space(parts[0])
	right := trim_space(parts[1])

	# Try left side as context, right side as value
	result := check_pair(left, right)
	result.is_vulnerable
} else = result {
	contains(expr, "==")
	not contains(expr, "!=")  # Exclude != operator
	parts := split(expr, "==")
	count(parts) == 2

	left := trim_space(parts[0])
	right := trim_space(parts[1])

	# Try right side as context, left side as value
	result := check_pair(right, left)
	result.is_vulnerable
} else = {"is_vulnerable": false, "context": ""}

# Check if a context/value pair represents a bot check
check_pair(context_raw, value_raw) = result {
	# Remove quotes and handle different access patterns
	context := extract_context_path(context_raw)
	value := trim(value_raw, "\"'")

	# Check if it's a name-based bot check
	is_spoofable_name_context(context)
	is_bot_name(value)
	result := {"is_vulnerable": true, "context": context}
} else = result {
	# Remove quotes and handle different access patterns
	context := extract_context_path(context_raw)
	value := trim(value_raw, "\"'")

	# Check if it's an ID-based bot check
	is_spoofable_id_context(context)
	is_bot_id(value)
	result := {"is_vulnerable": true, "context": context}
} else = {"is_vulnerable": false, "context": ""}

# Extract context path from various GitHub expression formats
# Handles: github.actor, github['actor'], GITHUB.actor, GitHub['ACTOR']
extract_context_path(raw) = result {
	# Remove any brackets and quotes to normalize
	cleaned := replace(replace(replace(raw, "[", "."), "]", ""), "'", "")
	cleaned2 := replace(cleaned, "\"", "")
	result := lower(cleaned2)
}

# Job-level bot condition check
CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j].if

	bot_check := check_bot_condition_in_expression(job)
	bot_check.is_vulnerable

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.if={{%v}}", [j, bot_check]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Job condition should use non-spoofable actor context",
		"keyActualValue": sprintf("Job uses spoofable actor context '%s' in bot check", [bot_check.context]),
		"searchLine": common_lib.build_search_line(["jobs", j, "if"], []),
		"resourceType": "github_action",
		"resourceName": j
	}
}

# Step-level bot condition check
CxPolicy[result] {
	doc := input.document[i]
	job := doc.jobs[j]

	step_obj := job.steps[k]
	step_if := step_obj.if

	bot_check := check_bot_condition_in_expression(step_if)
	bot_check.is_vulnerable
	step_name := object.get(step_obj, "name", sprintf("step-%d", [k]))

	result := {
		"documentId": doc.id,
		"searchKey": sprintf("jobs.%s.steps[%d].if={{%s}}", [j, k, step_if]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Step condition should use non-spoofable actor context",
		"keyActualValue": sprintf("Step uses spoofable actor context '%s' in bot check", [bot_check.context]),
		"searchLine": common_lib.build_search_line(["jobs", j, "steps", k, "if"], []),
		"resourceType": "github_action",
		"resourceName": step_name
	}
}
