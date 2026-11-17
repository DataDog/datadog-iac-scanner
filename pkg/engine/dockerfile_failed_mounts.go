package engine

// projectDockerFailedRunMountInventories adds an opaque open-inventory marker
// when RUN mount expansion failed. The parser can still recover command facts,
// but an absent mount cannot be treated as proof that no cache mount exists.
func projectDockerFailedRunMountInventories(facts map[string]interface{}, placeholder string) {
	instructions, _ := facts["instructions"].([]interface{})
	for _, raw := range instructions {
		if instruction, ok := raw.(map[string]interface{}); ok {
			projectDockerFailedRunMountInstruction(instruction, placeholder)
		}
	}
}

func projectDockerFailedRunMountInstruction(instruction map[string]interface{}, placeholder string) {
	if instruction["kind"] == "run" && instruction["parse_ok"] == false {
		instruction["mounts"] = append(asDockerList(instruction["mounts"]), placeholder)
	}
	if trigger, ok := instruction["trigger"].(map[string]interface{}); ok {
		projectDockerFailedRunMountInstruction(trigger, placeholder)
	}
}
