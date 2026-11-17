package engine

const dockerShellForm = "shell"

// Runtime shell commands have known Dockerfile syntax, but their execution
// depends on runtime context. One unknown execution record preserves that
// distinction without fabricating independent inventories of future commands.
func projectDockerRuntimeExecution(facts map[string]interface{}, placeholder string) {
	instructions, _ := facts["instructions"].([]interface{})
	for _, raw := range instructions {
		if instruction, ok := raw.(map[string]interface{}); ok {
			projectDockerRuntimeInstruction(instruction, placeholder)
		}
	}
}

func projectDockerRuntimeInstruction(instruction map[string]interface{}, placeholder string) {
	if instruction["kind"] == "cmd" || instruction["kind"] == "entrypoint" {
		if execution, ok := instruction["execution"].(map[string]interface{}); ok && execution["form"] == dockerShellForm {
			instruction["execution"] = placeholder
		}
	}
	if trigger, ok := instruction["trigger"].(map[string]interface{}); ok {
		projectDockerRuntimeInstruction(trigger, placeholder)
	}
}
