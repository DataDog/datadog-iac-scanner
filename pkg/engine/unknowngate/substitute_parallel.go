/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package unknowngate

import (
	"context"
	"sync/atomic"

	"github.com/open-policy-agent/opa/v1/ast"
)

const maxParallelSubstitutionWorkers = 4

type groupOutcome[T any] struct {
	value T
	err   error
}

// parallelInputGroups checks groups in index order. The caller executes the
// first and any groups for which no extra budget is available; at most three
// additional workers run concurrently. On error or cancellation it stops
// dispatching, joins started workers, and returns the earliest started error.
func parallelInputGroups[Group, Result any](
	ctx context.Context,
	groups []Group,
	tryAcquire func() (release func(), ok bool),
	fn func(context.Context, Group) (Result, error),
) ([]Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(groups) == 0 {
		return nil, nil
	}

	outcomes := make([]groupOutcome[Result], len(groups))
	stop := atomic.Bool{}
	run := func(i int) {
		outcomes[i].value, outcomes[i].err = fn(ctx, groups[i])
		if outcomes[i].err != nil {
			stop.Store(true)
		}
	}
	run(0)

	workers := groupWorkers{done: make(chan struct{}, maxParallelSubstitutionWorkers-1)}
	next := 1
	for next < len(groups) || workers.active > 0 {
		workers.drain()
		if groupWorkStopped(ctx, &stop) {
			workers.join()
			break
		}
		for next < len(groups) && !groupWorkStopped(ctx, &stop) {
			i := next
			if !workers.start(tryAcquire, func() { run(i) }) {
				break
			}
			next++
		}
		if groupWorkStopped(ctx, &stop) {
			continue
		}
		if next < len(groups) {
			i := next
			next++
			run(i)
		} else if workers.active > 0 {
			workers.wait()
		}
	}
	return collectGroupResults(ctx, outcomes, next)
}

func groupWorkStopped(ctx context.Context, stopped *atomic.Bool) bool {
	return stopped.Load() || ctx.Err() != nil
}

// groupWorkers tracks borrowed slots on the caller; workers only signal completion.
type groupWorkers struct {
	done   chan struct{}
	active int
}

func (w *groupWorkers) start(tryAcquire func() (func(), bool), run func()) bool {
	if tryAcquire == nil || w.active >= maxParallelSubstitutionWorkers-1 {
		return false
	}
	release, ok := tryAcquire()
	if !ok {
		return false
	}
	w.active++
	go func() {
		defer func() {
			if release != nil {
				release()
			}
			w.done <- struct{}{}
		}()
		run()
	}()
	return true
}

func (w *groupWorkers) drain() {
	for {
		select {
		case <-w.done:
			w.active--
		default:
			return
		}
	}
}

func (w *groupWorkers) wait() {
	<-w.done
	w.active--
}

func (w *groupWorkers) join() {
	for w.active > 0 {
		w.wait()
	}
}

func collectGroupResults[T any](ctx context.Context, outcomes []groupOutcome[T], started int) ([]T, error) {
	results := make([]T, len(outcomes))
	for i := 0; i < started; i++ {
		outcome := outcomes[i]
		results[i] = outcome.value
		if outcome.err != nil {
			return results, outcome.err
		}
	}
	if err := ctx.Err(); err != nil {
		return results, err
	}
	return results, nil
}

// parallelRoundWindow runs offset zero on the caller and borrows up to three
// CPU slots for later offsets. It joins every started round before returning.
func parallelRoundWindow[T any](
	ctx context.Context,
	count int,
	tryAcquire func() (func(), bool),
	fn func(offset int) (T, error),
) []groupOutcome[T] {
	if count <= 0 {
		return nil
	}
	outcomes := make([]groupOutcome[T], count)
	stop := atomic.Bool{}
	run := func(i int) {
		outcomes[i].value, outcomes[i].err = fn(i)
		if outcomes[i].err != nil {
			stop.Store(true)
		}
	}
	workers := groupWorkers{done: make(chan struct{}, maxParallelSubstitutionWorkers-1)}
	next := 1
	for next < count && !groupWorkStopped(ctx, &stop) {
		i := next
		if !workers.start(tryAcquire, func() { run(i) }) {
			break
		}
		next++
	}
	// The caller always runs offset zero, even if a speculative later round
	// fails; ordered aggregation decides which error is observable.
	run(0)
	workers.join()
	return outcomes[:next]
}

// batchRoundsArePure limits speculative rounds to known deterministic builtins
// without `with` modifiers or logging. Unknown/custom operators stay serial.
func batchRoundsArePure(rules *compiledRules) bool {
	if rules == nil {
		return false
	}
	for rule := range rules.meta {
		unsafe := false
		ast.WalkExprs(rule, func(e *ast.Expr) bool {
			if len(e.With) > 0 {
				unsafe = true
				return false
			}
			if !e.IsCall() || e.IsEquality() {
				return false
			}
			name := e.Operator().String()
			if name == ast.Print.Name || name == ast.Trace.Name || name == ast.InternalPrint.Name {
				unsafe = true
				return false
			}
			if builtin, ok := ast.BuiltinMap[name]; ok {
				if builtin.Nondeterministic {
					unsafe = true
				}
				return false
			}
			if !e.Operator().HasPrefix(ast.DefaultRootRef) {
				unsafe = true
			}
			return false
		})
		if unsafe {
			return false
		}
	}
	return true
}
