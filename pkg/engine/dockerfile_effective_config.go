package engine

// projectUnknownDockerEffectiveConfig keeps missing effective image settings
// unknown at the policy boundary. The *_set fields remain known facts about
// locally authored or locally inherited directives.
func projectUnknownDockerEffectiveConfig(facts map[string]interface{}, placeholder string) {
	contexts, _ := facts["contexts"].([]interface{})
	usedContexts := make(map[int]bool)
	stages, _ := facts["stages"].([]interface{})
	for _, raw := range stages {
		stage, _ := raw.(map[string]interface{})
		if stage == nil {
			continue
		}
		if index, ok := dockerFactIndex(stage["context"]); ok && index >= 0 {
			usedContexts[index] = true
		}
	}
	instructions, _ := facts["instructions"].([]interface{})
	for _, raw := range instructions {
		instruction, _ := raw.(map[string]interface{})
		if instruction == nil {
			continue
		}
		if stage, ok := dockerFactIndex(instruction["stage"]); ok && stage >= 0 {
			collectDockerInstructionContexts(instruction, usedContexts)
		}
	}
	for index := range usedContexts {
		if index >= len(contexts) {
			continue
		}
		if context, ok := contexts[index].(map[string]interface{}); ok {
			projectDockerEffectiveContext(context, placeholder)
		}
	}
}

func collectDockerInstructionContexts(instruction map[string]interface{}, contexts map[int]bool) {
	if index, ok := dockerFactIndex(instruction["context"]); ok && index >= 0 {
		contexts[index] = true
	}
	if trigger, ok := instruction["trigger"].(map[string]interface{}); ok {
		collectDockerInstructionContexts(trigger, contexts)
	}
}

func projectDockerEffectiveContext(context map[string]interface{}, placeholder string) {
	if context["user_set"] != true {
		context["user"] = placeholder
		context["user_name"] = placeholder
	}
	if workdir, ok := context["workdir"].(map[string]interface{}); !ok || workdir["known"] == false {
		context["workdir"] = placeholder
	}
	if context["healthcheck_set"] != true {
		context["healthcheck"] = placeholder
	}
	if context["shell_known"] != true {
		context["shell"] = placeholder
		context["shell_known"] = placeholder
	}
	// The base image can add arbitrary environment keys. Keep this map
	// opaque rather than treating an unwritten key as absent.
	context["environment_values"] = placeholder
}
