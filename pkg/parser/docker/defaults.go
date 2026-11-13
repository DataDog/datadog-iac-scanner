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
	if value, ok := environment.lookup(environment.environment, name); ok {
		return value, true
	}
	return environment.lookup(environment.arguments, name)
}
func (valueEnvironment) Keys() []string { return nil }

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
	result := value(raw)
	if result.Known {
		return result
	}
	lexer := buildkitshell.NewLex('\\')
	lexer.SkipUnsetEnv = true
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
	result := image(raw, state.result.Stages[:state.current])
	if result.Reference.Known {
		return result
	}
	candidate := defaultCandidate(raw, valueEnvironment{state: state, environment: -1, arguments: state.result.GlobalArguments})
	result.Reference = candidate
	if candidate.Default != nil {
		result.Default = image(*candidate.Default, state.result.Stages[:state.current])
	}
	return result
}
