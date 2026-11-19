package docker

import (
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/shell"
	dockercommand "github.com/moby/buildkit/frontend/dockerfile/command"
)

// invalidateOnbuildConfig applies the conservative effects of a base image's
// ONBUILD triggers to the child stage's inherited configuration. Trigger
// directives execute in the child after FROM; their effective values may depend
// on downstream bindings and earlier triggers, so this model keeps affected
// settings conservative rather than executing the triggers.
func (state *analysisState) invalidateOnbuildConfig(index int) {
	if index < 0 || index >= len(state.result.Instructions) {
		state.invalidateAllInheritedConfig()
		return
	}
	entry := &state.result.Instructions[index]
	if state.invalidOnbuild[index] || !entry.ParseOK {
		state.invalidateAllInheritedConfig()
		return
	}
	if !knownOnbuildTriggerKind(entry.TriggerKind) {
		state.invalidateAllInheritedConfig()
		return
	}
	switch entry.TriggerKind {
	case dockercommand.User:
		state.context.User = shell.Value{}
		unknown := shell.Value{}
		state.context.UserName = &unknown
		state.context.UserSet = true
		state.context.UserSetUnknown = false
		state.context.UserInstruction = -1
		state.context.UserInstructionUnknown = true
	case dockercommand.Healthcheck:
		state.context.Healthcheck = &Healthcheck{}
		state.context.HealthcheckSet = true
		state.context.HealthcheckSetUnknown = false
	case dockercommand.Shell:
		state.invalidateShell()
	case dockercommand.Env:
		state.context.Environment = -2
	case dockercommand.Arg:
		state.context.Arguments = -2
	case dockercommand.Workdir:
		state.context.Workdir = shell.Value{}
	case dockercommand.Run:
		// The command inventory is marked unknown after it is assembled.
	case dockercommand.Add, dockercommand.Cmd, dockercommand.Copy, dockercommand.Entrypoint,
		dockercommand.Expose, dockercommand.Label, dockercommand.Maintainer,
		dockercommand.StopSignal, dockercommand.Volume:
		// These triggers do not change configuration facts tracked here.
	}
}

func knownOnbuildTriggerKind(kind string) bool {
	switch kind {
	case dockercommand.Add, dockercommand.Arg, dockercommand.Cmd, dockercommand.Copy,
		dockercommand.Entrypoint, dockercommand.Env, dockercommand.Expose,
		dockercommand.Healthcheck, dockercommand.Label, dockercommand.Maintainer,
		dockercommand.Run, dockercommand.Shell, dockercommand.StopSignal,
		dockercommand.User, dockercommand.Volume, dockercommand.Workdir:
		return true
	default:
		return false
	}
}

func (state *analysisState) invalidateAllInheritedConfig() {
	state.context.Environment = -2
	state.context.Arguments = -2
	state.context.User = shell.Value{}
	unknownUser := shell.Value{}
	state.context.UserName = &unknownUser
	state.context.UserSet = false
	state.context.UserSetUnknown = true
	state.context.UserInstruction = -1
	state.context.UserInstructionUnknown = true
	state.context.Workdir = shell.Value{}
	state.invalidateShell()
	state.context.Healthcheck = &Healthcheck{}
	state.context.HealthcheckSet = false
	state.context.HealthcheckSetUnknown = true
}

func (state *analysisState) invalidateShell() {
	state.currentShell = nil
	state.context.Shell = nil
	state.context.ShellKnown = false
	if state.current >= 0 && state.current < len(state.stageShells) {
		state.stageShells[state.current] = nil
	}
}

func (state *analysisState) invalidateFailedInstruction(kind string, index int) {
	switch kind {
	case dockercommand.User:
		state.context.User = shell.Value{}
		unknown := shell.Value{}
		state.context.UserName = &unknown
		state.context.UserSet = true
		state.context.UserSetUnknown = false
		state.context.UserInstruction = index
		state.context.UserInstructionUnknown = false
	case dockercommand.Healthcheck:
		state.context.Healthcheck = &Healthcheck{}
		state.context.HealthcheckSet = true
		state.context.HealthcheckSetUnknown = true
	case dockercommand.Shell:
		state.invalidateShell()
	case dockercommand.Env:
		state.context.Environment = -2
	case dockercommand.Arg:
		state.context.Arguments = -2
		if state.current < 0 {
			state.result.GlobalArguments = -2
		}
	case dockercommand.Workdir:
		state.context.Workdir = shell.Value{}
	}
}

func assignInheritedOnbuildRunCommandUnknowns(analysis *Analysis) {
	if analysis == nil {
		return
	}
	for stageIndex := range analysis.Stages {
		stage := &analysis.Stages[stageIndex]
		unknown := false
		for _, instructionIndex := range stage.InheritedOnbuild {
			if instructionIndex < 0 || instructionIndex >= len(analysis.Instructions) {
				unknown = true
				break
			}
			instruction := &analysis.Instructions[instructionIndex]
			if instruction.TriggerKind == dockercommand.Run || !knownOnbuildTriggerKind(instruction.TriggerKind) ||
				!instruction.ParseOK || instruction.Trigger == nil || !instruction.Trigger.ParseOK {
				unknown = true
				break
			}
		}
		if unknown {
			stage.RunCommands = append(stage.RunCommands, shell.Value{})
		}
	}
}
