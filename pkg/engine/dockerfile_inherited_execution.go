package engine

const dockerRunInstructionKind = "run"

// taintUnknownDockerInheritedExecution prevents shell-derived facts from
// being treated as facts about a known interpreter when an external image's
// SHELL configuration was not fetched or the stage inherits an unknown local
// base. Exec-form argv and explicit SHELL/heredoc interpreters remain known.
func taintUnknownDockerInheritedExecution(facts map[string]interface{}, placeholder string) {
	instructions, _ := facts["instructions"].([]interface{})
	unknownRunStages := make(map[int]bool)
	for _, rawInstruction := range instructions {
		instruction, ok := rawInstruction.(map[string]interface{})
		if !ok {
			continue
		}
		unknownExecution := taintDockerInstructionExecutions(instruction, placeholder)
		if unknownExecution && instruction["kind"] == dockerRunInstructionKind {
			stage, ok := dockerFactIndex(instruction["stage"])
			if !ok || stage < 0 {
				continue
			}
			unknownRunStages[stage] = true
		}
	}
	contexts, _ := facts["contexts"].([]interface{})
	for _, rawContext := range contexts {
		if context, ok := rawContext.(map[string]interface{}); ok {
			taintDockerHealthcheckExecution(context, placeholder)
		}
	}

	rebuildUnknownDockerStageRunCommands(facts, unknownRunStages, placeholder)
}

func taintDockerInstructionExecutions(instruction map[string]interface{}, placeholder string) bool {
	unknownExecution := taintDockerExecutionOwner(instruction, placeholder)
	if healthcheck, ok := instruction["healthcheck"].(map[string]interface{}); ok {
		taintDockerHealthcheckFact(healthcheck, placeholder)
	}
	if trigger, ok := instruction["trigger"].(map[string]interface{}); ok {
		taintDockerInstructionExecutions(trigger, placeholder)
	}
	return unknownExecution
}

func taintDockerHealthcheckExecution(owner map[string]interface{}, placeholder string) {
	healthcheck, ok := owner["healthcheck"].(map[string]interface{})
	if !ok {
		return
	}
	taintDockerHealthcheckFact(healthcheck, placeholder)
}

func taintDockerHealthcheckFact(healthcheck map[string]interface{}, placeholder string) {
	taintDockerExecutionOwner(healthcheck, placeholder)
}

func taintDockerExecutionOwner(owner map[string]interface{}, placeholder string) bool {
	execution, ok := owner["execution"].(map[string]interface{})
	if !ok {
		return false
	}
	if execution["form"] != dockerShellForm || execution["shell_known"] != false {
		return false
	}
	// All semantic facts depend on which shell receives this script. The
	// Dockerfile-authored form and script remain available in the separate
	// `syntax` field.
	owner["execution"] = placeholder
	return true
}

func rebuildUnknownDockerStageRunCommands(facts map[string]interface{}, unknownStages map[int]bool, placeholder string) {
	if len(unknownStages) == 0 {
		return
	}
	stages, _ := facts["stages"].([]interface{})
	instructions, _ := facts["instructions"].([]interface{})
	commands := make(map[int][]interface{}, len(unknownStages))
	seen := make(map[int]map[string]bool, len(unknownStages))
	collectKnownDockerStageRunCommands(instructions, unknownStages, commands, seen)
	for index, rawStage := range stages {
		if !unknownStages[index] {
			continue
		}
		stage, ok := rawStage.(map[string]interface{})
		if !ok {
			continue
		}
		commands[index] = append(commands[index], placeholder)
		stage["run_commands"] = commands[index]
	}
}

func collectKnownDockerStageRunCommands(
	instructions []interface{}, unknownStages map[int]bool,
	commands map[int][]interface{}, seen map[int]map[string]bool,
) {
	for _, rawInstruction := range instructions {
		instruction, ok := rawInstruction.(map[string]interface{})
		if !ok || instruction["kind"] != dockerRunInstructionKind {
			continue
		}
		stage, ok := dockerFactIndex(instruction["stage"])
		if !ok || !unknownStages[stage] {
			continue
		}
		execution, ok := instruction["execution"].(map[string]interface{})
		if !ok {
			continue
		}
		calls, _ := execution["calls"].([]interface{})
		for _, rawCall := range calls {
			name, ok := knownDockerRunCallName(rawCall)
			if !ok {
				continue
			}
			if seen[stage] == nil {
				seen[stage] = make(map[string]bool)
			}
			if seen[stage][name] {
				continue
			}
			seen[stage][name] = true
			commands[stage] = append(commands[stage], map[string]interface{}{"value": name, "known": true})
		}
	}
}

func knownDockerRunCallName(rawCall interface{}) (string, bool) {
	call, ok := rawCall.(map[string]interface{})
	if !ok || call["deferred"] == true || call["function"] == true {
		return "", false
	}
	executable, ok := call["executable"].(map[string]interface{})
	if !ok {
		return "", false
	}
	name, ok := call["name"].(string)
	if !ok || name == "" {
		return "", false
	}
	known, ok := executable["known"].(bool)
	return name, ok && known
}
