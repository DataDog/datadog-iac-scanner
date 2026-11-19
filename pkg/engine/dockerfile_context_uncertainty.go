package engine

// projectDockerUnknownContextSetters turns parser-only uncertainty flags into
// opaque policy values before effective stage configuration is projected.
func projectDockerUnknownContextSetters(facts map[string]interface{}, placeholder string) {
	if index, ok := dockerFactIndex(facts["global_arguments"]); ok && index == -2 {
		facts["global_arguments"] = placeholder
	}
	bindings, _ := facts["bindings"].([]interface{})
	for _, raw := range bindings {
		if binding, ok := raw.(map[string]interface{}); ok {
			projectDockerUnknownBindingFrame(binding, "parent", placeholder)
		}
	}
	contexts, _ := facts["contexts"].([]interface{})
	for _, raw := range contexts {
		context, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		projectDockerUnknownContextField(context, "user_set_unknown", "user_set", placeholder)
		projectDockerUnknownContextField(context, "user_instruction_unknown", "user_instruction", placeholder)
		projectDockerUnknownContextField(context, "healthcheck_set_unknown", "healthcheck_set", placeholder)
		projectDockerUnknownBindingFrame(context, "arguments", placeholder)
		projectDockerUnknownBindingFrame(context, "environment", placeholder)
		if context["deferred"] == true {
			context["user_instruction"] = placeholder
		}
	}
}

func projectDockerUnknownContextField(context map[string]interface{}, marker, field, placeholder string) {
	if context[marker] == true {
		context[field] = placeholder
	}
	delete(context, marker)
}

func projectDockerUnknownBindingFrame(object map[string]interface{}, field, placeholder string) {
	if index, ok := dockerFactIndex(object[field]); ok && index == -2 {
		object[field] = placeholder
	}
}

// projectDockerUnknownStageRunCommands makes the canonical RUN command
// inventory open when the parser records an unknown member.
func projectDockerUnknownStageRunCommands(facts map[string]interface{}, placeholder string) {
	stages, _ := facts["stages"].([]interface{})
	for _, raw := range stages {
		stage, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		commands, ok := stage["run_commands"].([]interface{})
		if !ok {
			continue
		}
		known := make([]interface{}, 0, len(commands)+1)
		open := false
		for _, rawCommand := range commands {
			if rawCommand == placeholder {
				open = true
				continue
			}
			command, ok := rawCommand.(map[string]interface{})
			if ok && command["known"] == false {
				open = true
				continue
			}
			known = append(known, rawCommand)
		}
		if open {
			known = append(known, placeholder)
			stage["run_commands"] = known
		}
	}
}
