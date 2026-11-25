/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package shell

// ScopeKind identifies the syntactic execution scope of a shell construct.
type ScopeKind string

const (
	ScopeScript              ScopeKind = "script"
	ScopeSubshell            ScopeKind = "subshell"
	ScopeCommandSubstitution ScopeKind = "command_substitution"
	ScopeProcessSubstitution ScopeKind = "process_substitution"
	ScopeFunction            ScopeKind = "function"
	ScopePipeline            ScopeKind = "pipeline"
	ScopePipelineStage       ScopeKind = "pipeline_stage"
	ScopeConditional         ScopeKind = "conditional"
	ScopeBackground          ScopeKind = "background"
	ScopeCoprocess           ScopeKind = "coprocess"
	ScopeShellScript         ScopeKind = "shell_script"
)

// GuardKind identifies whether a guard requires the referenced call to succeed or fail.
type GuardKind string

const (
	GuardSuccess GuardKind = "success"
	GuardFailure GuardKind = "failure"
)

// Value distinguishes a statically known word from an expansion. Raw preserves
// the source spelling; Text is useful only when Known is true.
type Value struct {
	Raw     string `json:"raw,omitempty"`
	Pattern string `json:"pattern,omitempty"`
	Text    string `json:"value"`
	Known   bool   `json:"known"`
}

// Scope represents a lexical or execution scope within a parsed shell script.
type Scope struct {
	ID     int       `json:"id"`
	Parent int       `json:"parent"`
	Kind   ScopeKind `json:"kind"`
}

// Guard records a success/failure dependency on another syntactic call.
type Guard struct {
	Kind GuardKind `json:"kind"`
	Call int       `json:"call"`
}

// Span is a byte range of the analyzed script. Calls of nested scripts share
// the span of the argument holding the script; exec-form calls have none.
type Span struct {
	Start, End int
}

// Invocation is syntactic, not proof that a branch executes.
// Function bodies are deferred; scopes preserve isolation and conditionality.
type Invocation struct {
	Guards           []Guard  `json:"guards,omitempty"`
	Name             string   `json:"name"`
	Executable       Value    `json:"executable"`
	Arguments        []Value  `json:"arguments"`
	CDPath           *Value   `json:"cd_path,omitempty"`
	DynamicArguments bool     `json:"dynamic_arguments,omitempty"`
	Wrappers         []string `json:"wrappers,omitempty"`
	Scope            int      `json:"scope"`
	Order            int      `json:"order"`
	Function         bool     `json:"function"`
	Deferred         bool     `json:"deferred"`
	Conditional      bool     `json:"conditional"`
	Span             Span     `json:"-"`
	ArgumentSpans    []Span   `json:"-"`
}

// Pipeline records a shell pipeline and the pipefail option state in its scope.
type Pipeline struct {
	Scope    int    `json:"scope"`
	Shell    string `json:"shell"`
	Pipefail bool   `json:"pipefail"`
	Known    bool   `json:"known"`
	Deferred bool   `json:"deferred"`
	Span     Span   `json:"-"`
}

// Facts holds structured command, pipeline, scope, and package-manager facts
// extracted from a shell script or exec-form argv.
type Facts struct {
	// EnvironmentMayChange records syntactic assignments or shell state
	// operations. They may be conditional or deferred; this does not claim
	// that the environment actually changes during execution.
	EnvironmentMayChange bool             `json:"environment_may_change,omitempty"`
	Pipelines            []Pipeline       `json:"pipelines,omitempty"`
	Calls                []Invocation     `json:"calls"`
	PackageCommands      []PackageCommand `json:"package_commands"`
	Scopes               []Scope          `json:"scopes"`
	Complete             bool             `json:"complete"`
	Diagnostics          []string         `json:"diagnostics,omitempty"`
}

func (f *Facts) validSameScopePair(earlier, later int) bool {
	if f == nil || earlier < 0 || later < 0 || earlier >= len(f.Calls) || later >= len(f.Calls) || earlier == later {
		return false
	}
	scope := f.Calls[later].Scope
	return f.Calls[earlier].Scope == scope && !scopeHasKind(f.Scopes, scope, ScopePipeline)
}

// SuccessPrecedes reports whether call index `earlier` must complete
// successfully before call index `later` can execute (via transitive `&&`
// guards within the same non-pipeline scope).
func (f *Facts) SuccessPrecedes(earlier, later int) bool {
	if !f.validSameScopePair(earlier, later) {
		return false
	}
	targetScope := f.Calls[later].Scope
	visited := make([]bool, len(f.Calls))
	stack := successGuardCalls(f.Calls[later].Guards)
	for len(stack) > 0 {
		last := len(stack) - 1
		idx := stack[last]
		stack = stack[:last]
		if idx < 0 || idx >= len(f.Calls) || visited[idx] || idx == later || f.Calls[idx].Scope != targetScope {
			continue
		}
		if idx == earlier {
			return true
		}
		visited[idx] = true
		stack = append(stack, successGuardCalls(f.Calls[idx].Guards)...)
	}
	return false
}

// Precedes reports whether call index `earlier` is syntactically guaranteed to
// execute before call index `later` within the same non-pipeline scope. Within
// conditional scopes or for conditional calls, only an explicit `&&` success
// dependency establishes precedence.
func (f *Facts) Precedes(earlier, later int) bool {
	if !f.validSameScopePair(earlier, later) {
		return false
	}
	prev, cur := f.Calls[earlier], f.Calls[later]
	if prev.Order >= cur.Order {
		return false
	}
	conditionalScope := scopeHasKind(f.Scopes, cur.Scope, ScopeConditional)
	if !conditionalScope && !cur.Conditional && !prev.Conditional {
		return true
	}
	return f.SuccessPrecedes(earlier, later)
}

func successGuardCalls(guards []Guard) []int {
	var calls []int
	for _, guard := range guards {
		if guard.Kind == GuardSuccess {
			calls = append(calls, guard.Call)
		}
	}
	return calls
}

func scopeHasKind(scopes []Scope, scope int, kind ScopeKind) bool {
	for scope >= 0 && scope < len(scopes) {
		if scopes[scope].Kind == kind {
			return true
		}
		scope = scopes[scope].Parent
	}
	return false
}
