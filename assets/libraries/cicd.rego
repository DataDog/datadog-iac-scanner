package generic.cicd

import rego.v1

dangerous_triggers := ["pull_request_target", "workflow_run"]

# Check if workflow has dangerous triggers
has_dangerous_trigger(doc) if {
	trigger := doc.on
	trigger == dangerous_triggers[_]
}

has_dangerous_trigger(doc) if {
	trigger := doc.on[_]
	trigger == dangerous_triggers[_]
}

has_dangerous_trigger(doc) if {
	doc.on[trigger]
	trigger == dangerous_triggers[_]
}

# Composite GitHub Actions (action.yml) declare their kind via `runs.using` and
# carry steps under `doc.runs.steps[*]` rather than `doc.jobs[*].steps[*]`. They
# inherit the trigger context from the calling workflow, so step-level rules
# cannot use `doc.on` for them.
is_composite_action(doc) if {
	doc.runs.using == "composite"
}

# True when the raw text of a parsed GitHub Actions expression references a
# directly attacker-influenced context: `inputs.*`, `github.event.*`,
# `github.head_ref`, or `github.pull_request.*`.
references_untrusted_context(raw) if {
	contains(raw, "inputs.")
}

references_untrusted_context(raw) if {
	contains(raw, "github.event.")
}

references_untrusted_context(raw) if {
	contains(raw, "github.head_ref")
}

references_untrusted_context(raw) if {
	contains(raw, "github.pull_request.")
}

# True for AST dereferences rooted at the `inputs` context (`inputs.<X>`),
# but not for `github.event.inputs.<X>`, whose root is `github`.
is_bare_inputs_dereference(node) if {
	node.type == "dereference_expression"
	obj := node.children[0]
	obj.type == "identifier"
	lower(obj.value) == "inputs"
}

check_provider(doc) := "github" if {
	contains(doc._path, "/.github/")
} else := "github" if {
	regex.match("/action\\.ya?ml", doc._path)
} else := "github" if {
	contains(doc._path, "\\.github\\")
} else := "github" if {
	regex.match("\\\\action\\.ya?ml", doc._path)
} else := "other"
