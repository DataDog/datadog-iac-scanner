/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/DataDog/datadog-iac-scanner/pkg/policy"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

type entityCompilation struct {
	compiler     *ast.Compiler
	capabilities *ast.Capabilities
	functions    []entityFunction
	decisions    map[string]string
}

func compileEntitySources(sources, libraries map[string]string) (*entityCompilation, error) {
	modules, decisions, err := entityModules(sources, libraries)
	if err != nil {
		return nil, err
	}
	functions := entityFunctions()
	caps := *safeCapabilities()
	caps.Builtins = slices.DeleteFunc(slices.Clone(caps.Builtins), func(b *ast.Builtin) bool { return b.Nondeterministic })
	for _, f := range functions {
		caps.Builtins = append(caps.Builtins, &ast.Builtin{Name: f.definition.Name, Decl: f.definition.Decl})
	}
	compiler := ast.NewCompiler().WithCapabilities(&caps)
	compiler.Compile(modules)
	if compiler.Failed() {
		return nil, compiler.Errors
	}
	return &entityCompilation{compiler: compiler, capabilities: &caps, functions: functions, decisions: decisions}, nil
}

func (c *entityCompilation) options(decision string) []func(*rego.Rego) {
	options := []func(*rego.Rego){
		rego.Query("some finding in " + decision + "; result = finding"), rego.Compiler(c.compiler), rego.Capabilities(c.capabilities),
		rego.SetRegoVersion(ast.RegoV1), rego.StrictBuiltinErrors(true), rego.PartialNamespace(entityPartialNamespace),
	}
	for _, f := range c.functions {
		options = append(options, f.option)
	}
	return options
}

// OPA partial copy propagation can mutate arrays borrowed from compiled
// literals. Its workspace must not share ASTs with native evaluation or with
// another concurrent partial run. One lazily prepared workspace is leased
// through materialization; native programs remain independently concurrent.
// Infrastructure values stay in the caller's reader, never in this workspace.
type entitySymbolicWorkspace struct {
	gate               chan struct{}
	sources, libraries map[string]string
	programs           map[string]rego.PreparedPartialQuery
}

func newEntitySymbolicWorkspace(sources, libraries map[string]string) *entitySymbolicWorkspace {
	return &entitySymbolicWorkspace{gate: make(chan struct{}, 1), sources: maps.Clone(sources), libraries: maps.Clone(libraries)}
}

func (w *entitySymbolicWorkspace) evaluate(
	ctx context.Context, p *EntityProgram, input ast.Value, reader policy.Reader,
) (entityBatch, error) {
	select {
	case w.gate <- struct{}{}:
		defer func() { <-w.gate }()
	case <-ctx.Done():
		return entityBatch{}, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return entityBatch{}, err
	}
	if w.programs == nil {
		if err := w.prepare(ctx); err != nil {
			return entityBatch{}, err
		}
	}
	program, ok := w.programs[p.policyID]
	if !ok {
		return entityBatch{}, fmt.Errorf("missing symbolic program %q", p.policyID)
	}
	partial, err := program.Partial(ctx, rego.EvalParsedInput(input), rego.EvalUnknowns([]string{"input.__dd_symbols"}))
	if err != nil {
		return entityBatch{}, fmt.Errorf("symbolic entity evaluation: %w", err)
	}
	// Decode while holding the lease: no mutable residual/compiler nodes may
	// escape to a consumer or overlap the next partial evaluation.
	return p.symbolicFindings(partial, reader)
}

func (w *entitySymbolicWorkspace) prepare(ctx context.Context) error {
	compiled, err := compileEntitySources(w.sources, w.libraries)
	if err != nil {
		return err
	}
	programs := make(map[string]rego.PreparedPartialQuery, len(compiled.decisions))
	for id, decision := range compiled.decisions {
		prepared, err := rego.New(compiled.options(decision)...).PrepareForPartial(ctx)
		if err != nil {
			return err
		}
		programs[id] = prepared
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Publish only a complete workspace. Cancellation leaves initialization
	// retryable for the next invocation instead of poisoning a shared program.
	w.programs = programs
	w.sources, w.libraries = nil, nil
	return nil
}
