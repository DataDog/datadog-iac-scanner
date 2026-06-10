# Test assets/libraries/cicd.rego
# Make sure you have OPA version 0.49.2 installed
# Run from repo root using `opa test assets/libraries/ -v`
package generic.cicd

import rego.v1

# Test dangerous_triggers constant
test_dangerous_triggers_list if {
	count(dangerous_triggers) == 2
	dangerous_triggers[0] == "pull_request_target"
	dangerous_triggers[1] == "workflow_run"
}

# Test has_dangerous_trigger - variant 1: doc.on as string
test_has_dangerous_trigger_string_match_pull_request_target if {
	doc := {"on": "pull_request_target"}
	has_dangerous_trigger(doc)
}

test_has_dangerous_trigger_string_match_workflow_run if {
	doc := {"on": "workflow_run"}
	has_dangerous_trigger(doc)
}

test_has_dangerous_trigger_string_no_match if {
	doc := {"on": "push"}
	not has_dangerous_trigger(doc)
}

# Test has_dangerous_trigger - variant 2: doc.on as array
test_has_dangerous_trigger_array_single_dangerous if {
	doc := {"on": ["pull_request_target"]}
	has_dangerous_trigger(doc)
}

test_has_dangerous_trigger_array_multiple_with_dangerous if {
	doc := {"on": ["push", "workflow_run"]}
	has_dangerous_trigger(doc)
}

test_has_dangerous_trigger_array_no_dangerous if {
	doc := {"on": ["push", "pull_request"]}
	not has_dangerous_trigger(doc)
}

# Test has_dangerous_trigger - variant 3: doc.on as object
test_has_dangerous_trigger_object_pull_request_target if {
	doc := {"on": {"pull_request_target": {}}}
	has_dangerous_trigger(doc)
}

test_has_dangerous_trigger_object_workflow_run if {
	doc := {"on": {"workflow_run": {"workflows": ["build"]}}}
	has_dangerous_trigger(doc)
}

test_has_dangerous_trigger_object_multiple_with_dangerous if {
	doc := {"on": {"push": {}, "pull_request_target": {}}}
	has_dangerous_trigger(doc)
}

test_has_dangerous_trigger_object_no_dangerous if {
	doc := {"on": {"push": {}, "pull_request": {}}}
	not has_dangerous_trigger(doc)
}

# Test is_composite_action
test_is_composite_action_true if {
	doc := {"runs": {"using": "composite"}}
	is_composite_action(doc)
}

test_is_composite_action_false_node if {
	doc := {"runs": {"using": "node20"}}
	not is_composite_action(doc)
}

test_is_composite_action_false_docker if {
	doc := {"runs": {"using": "docker"}}
	not is_composite_action(doc)
}

test_is_composite_action_no_runs if {
	doc := {"jobs": {}}
	not is_composite_action(doc)
}

# Test references_untrusted_context - inputs.*
test_references_untrusted_context_inputs if {
	raw := "${{ inputs.branch }}"
	references_untrusted_context(raw)
}

test_references_untrusted_context_inputs_multiple if {
	raw := "echo ${{ inputs.username }} ${{ inputs.password }}"
	references_untrusted_context(raw)
}

# Test references_untrusted_context - github.event.*
test_references_untrusted_context_github_event if {
	raw := "${{ github.event.issue.title }}"
	references_untrusted_context(raw)
}

test_references_untrusted_context_github_event_pull_request if {
	raw := "${{ github.event.pull_request.head.ref }}"
	references_untrusted_context(raw)
}

# Test references_untrusted_context - github.head_ref
test_references_untrusted_context_head_ref if {
	raw := "${{ github.head_ref }}"
	references_untrusted_context(raw)
}

test_references_untrusted_context_head_ref_in_command if {
	raw := "git checkout ${{ github.head_ref }}"
	references_untrusted_context(raw)
}

# Test references_untrusted_context - github.pull_request.*
test_references_untrusted_context_pull_request if {
	raw := "${{ github.pull_request.title }}"
	references_untrusted_context(raw)
}

test_references_untrusted_context_pull_request_number if {
	raw := "${{ github.pull_request.number }}"
	references_untrusted_context(raw)
}

# Test references_untrusted_context - safe contexts
test_references_untrusted_context_safe_github_sha if {
	raw := "${{ github.sha }}"
	not references_untrusted_context(raw)
}

test_references_untrusted_context_safe_github_ref if {
	raw := "${{ github.ref }}"
	not references_untrusted_context(raw)
}

test_references_untrusted_context_safe_github_actor if {
	raw := "${{ github.actor }}"
	not references_untrusted_context(raw)
}

test_references_untrusted_context_safe_secrets if {
	raw := "${{ secrets.TOKEN }}"
	not references_untrusted_context(raw)
}

test_references_untrusted_context_plain_text if {
	raw := "echo hello world"
	not references_untrusted_context(raw)
}

# Test is_bare_inputs_dereference
test_is_bare_inputs_dereference_true if {
	node := {
		"type": "dereference_expression",
		"children": [{
			"type": "identifier",
			"value": "inputs",
		}],
	}
	is_bare_inputs_dereference(node)
}

test_is_bare_inputs_dereference_case_insensitive if {
	node := {
		"type": "dereference_expression",
		"children": [{
			"type": "identifier",
			"value": "INPUTS",
		}],
	}
	is_bare_inputs_dereference(node)
}

test_is_bare_inputs_dereference_false_github_event if {
	node := {
		"type": "dereference_expression",
		"children": [{
			"type": "identifier",
			"value": "github",
		}],
	}
	not is_bare_inputs_dereference(node)
}

test_is_bare_inputs_dereference_false_wrong_type if {
	node := {
		"type": "identifier",
		"value": "inputs",
	}
	not is_bare_inputs_dereference(node)
}

test_is_bare_inputs_dereference_false_wrong_child_type if {
	node := {
		"type": "dereference_expression",
		"children": [{
			"type": "string",
			"value": "inputs",
		}],
	}
	not is_bare_inputs_dereference(node)
}

# Test check_provider - github via .github/ path
test_check_provider_github_workflows if {
	doc := {"_path": "/repo/.github/workflows/ci.yml"}
	result := check_provider(doc)
	result == "github"
}

test_check_provider_github_actions if {
	doc := {"_path": "/repo/.github/actions/custom/action.yml"}
	result := check_provider(doc)
	result == "github"
}

# Test check_provider - github via action.yml/action.yaml
test_check_provider_github_action_yml if {
	doc := {"_path": "/repo/custom-action/action.yml"}
	result := check_provider(doc)
	result == "github"
}

test_check_provider_github_action_yaml if {
	doc := {"_path": "/repo/custom-action/action.yaml"}
	result := check_provider(doc)
	result == "github"
}

test_check_provider_github_root_action if {
	doc := {"_path": "/action.yml"}
	result := check_provider(doc)
	result == "github"
}

# Test check_provider - other providers
test_check_provider_other_gitlab if {
	doc := {"_path": "/repo/.gitlab-ci.yml"}
	result := check_provider(doc)
	result == "other"
}

test_check_provider_other_circleci if {
	doc := {"_path": "/repo/.circleci/config.yml"}
	result := check_provider(doc)
	result == "other"
}

test_check_provider_other_random_file if {
	doc := {"_path": "/repo/some/file.yml"}
	result := check_provider(doc)
	result == "other"
}

test_check_provider_other_no_path if {
	doc := {}
	result := check_provider(doc)
	result == "other"
}

# Test edge cases - complex nested structures
test_has_dangerous_trigger_complex_workflow if {
	doc := {
		"on": {
			"push": {"branches": ["main"]},
			"pull_request_target": {"types": ["opened", "synchronize"]},
		},
		"jobs": {"test": {"runs-on": "ubuntu-latest"}},
	}
	has_dangerous_trigger(doc)
}

test_references_untrusted_context_multiple_types if {
	raw := "echo ${{ inputs.name }} from ${{ github.event.sender.login }}"
	references_untrusted_context(raw)
}

test_composite_action_with_steps if {
	doc := {"runs": {
		"using": "composite",
		"steps": [
			{"run": "echo hello"},
			{"uses": "actions/checkout@v2"},
		],
	}}
	is_composite_action(doc)
}
