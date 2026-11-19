package docker

import (
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/shell"
	buildkitshell "github.com/moby/buildkit/frontend/dockerfile/shell"
)

// Defaults are candidates for linting build defaults, never assertions about
// runtime values. Build arguments can still be overridden by the caller.
type valueEnvironment struct {
	state                  *analysisState
	environment, arguments int
}

func (environment valueEnvironment) Get(name string) (string, bool) {
	if environment.hasBinding(environment.environment, name) {
		return environment.lookup(environment.environment, name)
	}
	return environment.lookup(environment.arguments, name)
}
func (valueEnvironment) Keys() []string { return nil }

type knownEnvironment struct {
	state *analysisState
	frame int
}

func (environment knownEnvironment) Get(name string) (string, bool) {
	frame := environment.frame
	for remaining := len(environment.state.result.Bindings); frame >= 0 && remaining > 0; remaining-- {
		if frame >= len(environment.state.result.Bindings) {
			return "", false
		}
		current := environment.state.result.Bindings[frame]
		for i := len(current.Bindings) - 1; i >= 0; i-- {
			binding := current.Bindings[i]
			if binding.Name != name {
				continue
			}
			if binding.Value.Known {
				return binding.Value.Text, true
			}
			return "", false
		}
		frame = current.Parent
	}
	return "", false
}
func (knownEnvironment) Keys() []string { return nil }

func (environment valueEnvironment) hasBinding(frame int, name string) bool {
	for remaining := len(environment.state.result.Bindings); frame >= 0 && remaining > 0; remaining-- {
		if frame >= len(environment.state.result.Bindings) {
			return false
		}
		current := environment.state.result.Bindings[frame]
		for _, binding := range current.Bindings {
			if binding.Name == name {
				return true
			}
		}
		frame = current.Parent
	}
	return false
}

func (environment valueEnvironment) lookup(frame int, name string) (string, bool) {
	for remaining := len(environment.state.result.Bindings); frame >= 0 && remaining > 0; remaining-- {
		if frame >= len(environment.state.result.Bindings) {
			return "", false
		}
		current := environment.state.result.Bindings[frame]
		for i := len(current.Bindings) - 1; i >= 0; i-- {
			binding := current.Bindings[i]
			if binding.Name != name {
				continue
			}
			// An ARG without a value keeps the global default: a global one
			// keeps the earlier declaration, a stage one imports it.
			if !binding.HasDefault && current.Kind == argumentBindings {
				if frame <= environment.state.result.GlobalArguments {
					continue
				}
				return environment.lookup(environment.state.result.GlobalArguments, name)
			}
			if binding.Value.Known {
				return binding.Value.Text, true
			}
			if binding.Value.Default != nil {
				return *binding.Value.Default, true
			}
			return "", false
		}
		frame = current.Parent
	}
	return "", false
}

func defaultCandidate(raw string, environment valueEnvironment) shell.Value {
	state := environment.state
	result := state.value(raw)
	if result.Known {
		return result
	}
	lexer := buildkitshell.NewLex(state.escape)
	lexer.SkipUnsetEnv = true
	known, err := lexer.ProcessWordWithMatches(raw, knownEnvironment{state: state, frame: environment.environment})
	if err == nil && len(known.Unmatched) == 0 {
		result.Text = known.Result
		result.Known = true
		return result
	}
	expanded, err := lexer.ProcessWordWithMatches(raw, environment)
	if err == nil && len(expanded.Unmatched) == 0 {
		result.Default = &expanded.Result
	}
	return result
}

func (state *analysisState) declaredValue(raw string) shell.Value {
	return defaultCandidate(raw, valueEnvironment{state: state, environment: state.context.Environment, arguments: state.context.Arguments})
}

func (state *analysisState) imageFact(raw string) *Image {
	result := state.image(raw, state.result.Stages[:state.current])
	if result.Reference.Known {
		return result
	}
	candidate := defaultCandidate(raw, valueEnvironment{state: state, environment: -1, arguments: state.result.GlobalArguments})
	result.Reference = candidate
	return result
}
