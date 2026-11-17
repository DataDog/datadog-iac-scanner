package docker

import "github.com/DataDog/datadog-iac-scanner/pkg/parser/shell"

const dockerRunInstruction = "run"

// assignStageRunCommands builds an inventory after parsing has completed, so
// every RUN in a syntactic stage gets the same complete view. This inventory
// says nothing about ordering or execution and does not follow FROM inheritance.
func assignStageRunCommands(analysis *Analysis) {
	if analysis == nil {
		return
	}
	commandsByStage, unknownByStage := collectStageRunCommands(analysis)
	for i := range analysis.Stages {
		stage := &analysis.Stages[i]
		stage.RunCommands = commandsByStage[stage.Index]
		if stage.RunCommands == nil {
			stage.RunCommands = []shell.Value{}
		}
		if unknownByStage[stage.Index] {
			stage.RunCommands = append(stage.RunCommands, shell.Value{Known: false})
		}
	}
}

func collectStageRunCommands(analysis *Analysis) (commandsByStage map[int][]shell.Value, unknownByStage map[int]bool) {
	commandsByStage = make(map[int][]shell.Value)
	knownByStage := make(map[int]map[string]struct{})
	unknownByStage = make(map[int]bool)

	for instructionIndex := range analysis.Instructions {
		instruction := &analysis.Instructions[instructionIndex]
		if instruction.Kind != dockerRunInstruction || instruction.Stage < 0 {
			continue
		}
		stage := instruction.Stage
		if instruction.Execution == nil || instruction.Execution.Facts == nil {
			unknownByStage[stage] = true
			continue
		}
		collectStageRunCallNames(stage, instruction.Execution.Calls, knownByStage, commandsByStage, unknownByStage)
		if !instruction.Execution.Complete {
			unknownByStage[stage] = true
		}
	}
	return commandsByStage, unknownByStage
}

func collectStageRunCallNames(stage int, calls []shell.Invocation,
	knownByStage map[int]map[string]struct{}, commandsByStage map[int][]shell.Value,
	unknownByStage map[int]bool) {
	for callIndex := range calls {
		call := &calls[callIndex]
		if call.Deferred || call.Function {
			continue
		}
		if !call.Executable.Known || call.Name == "" {
			unknownByStage[stage] = true
			continue
		}
		if knownByStage[stage] == nil {
			knownByStage[stage] = make(map[string]struct{})
		}
		if _, exists := knownByStage[stage][call.Name]; exists {
			continue
		}
		knownByStage[stage][call.Name] = struct{}{}
		commandsByStage[stage] = append(commandsByStage[stage], shell.Value{Text: call.Name, Known: true})
	}
}
