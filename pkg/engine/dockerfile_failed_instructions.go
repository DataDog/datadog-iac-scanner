package engine

import dockercommand "github.com/moby/buildkit/frontend/dockerfile/command"

// projectDockerFailedInstructionFacts preserves authored instruction metadata
// while making semantic facts absent after a parse failure explicitly unknown.
func projectDockerFailedInstructionFacts(facts map[string]interface{}, placeholder string) {
	instructions, _ := facts["instructions"].([]interface{})
	for _, raw := range instructions {
		if instruction, ok := raw.(map[string]interface{}); ok {
			projectDockerFailedInstruction(instruction, placeholder)
		}
	}
}

func projectDockerFailedInstruction(instruction map[string]interface{}, placeholder string) {
	if instruction["parse_ok"] == false {
		projectDockerFailedInstructionFields(instruction, placeholder)
	}
	trigger, ok := instruction["trigger"].(map[string]interface{})
	if !ok {
		return
	}
	projectDockerFailedInstruction(trigger, placeholder)
	projectDockerDeferredCopyRelation(trigger, placeholder)
}

func projectDockerFailedInstructionFields(instruction map[string]interface{}, placeholder string) {
	switch instruction["kind"] {
	case dockercommand.From:
		setDockerFactIfMissing(instruction, "image", placeholder)
	case dockercommand.Run:
		// RUN expansion can fail only for mount options while execution facts
		// remain valid. Preserve those facts when present.
		setDockerFactIfMissing(instruction, "execution", placeholder)
		setDockerFactIfMissing(instruction, "syntax", placeholder)
	case dockercommand.Cmd, dockercommand.Entrypoint:
		setDockerFactIfMissing(instruction, "execution", placeholder)
		setDockerFactIfMissing(instruction, "syntax", placeholder)
	case dockercommand.User, dockercommand.Workdir:
		setDockerFactIfMissing(instruction, "value", placeholder)
	case dockercommand.Copy, dockercommand.Add:
		setDockerFactIfMissing(instruction, dockercommand.Copy, placeholder)
	case dockercommand.Healthcheck:
		setDockerFactIfMissing(instruction, dockercommand.Healthcheck, placeholder)
	case dockercommand.Arg, dockercommand.Env, dockercommand.Label:
		appendDockerUnknownInventory(instruction, "bindings", placeholder)
	case dockercommand.Expose:
		appendDockerUnknownInventory(instruction, "values", placeholder)
		appendDockerUnknownInventory(instruction, "ports", placeholder)
	case dockercommand.Shell, dockercommand.Volume:
		appendDockerUnknownInventory(instruction, "values", placeholder)
	case dockercommand.Onbuild:
		setDockerFactIfMissing(instruction, "trigger", placeholder)
	}
}

func setDockerFactIfMissing(instruction map[string]interface{}, field, placeholder string) {
	if value, exists := instruction[field]; !exists || value == nil {
		instruction[field] = placeholder
	}
}

func appendDockerUnknownInventory(instruction map[string]interface{}, field, placeholder string) {
	instruction[field] = append(asDockerList(instruction[field]), placeholder)
}

// ONBUILD COPY --from relations are resolved in the child image's stage graph,
// which is unavailable while scanning the Dockerfile that declares the trigger.
func projectDockerDeferredCopyRelation(instruction map[string]interface{}, placeholder string) {
	if copyFacts, ok := instruction["copy"].(map[string]interface{}); ok && copyFacts["from"] != nil {
		copyFacts["source_stage"] = placeholder
	}
	if trigger, ok := instruction["trigger"].(map[string]interface{}); ok {
		projectDockerDeferredCopyRelation(trigger, placeholder)
	}
}
