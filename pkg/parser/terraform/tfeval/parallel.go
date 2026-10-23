/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"
	"iter"
	"maps"
	"runtime"
	"sync"

	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// parallelInstancesMin is the fewest instances a module call needs for them
// to be evaluated concurrently.
var parallelInstancesMin = 8

// concurrentInstances reports how many instances a call's plan has, when they
// are to be evaluated concurrently, or zero. Calls are only evaluated
// concurrently outside speculative evaluation, and outside another
// concurrent call: the outermost fan-out of a module tree is split, and
// everything under it is evaluated in order by the worker that took it.
func (e *Evaluator) concurrentInstances(plan *moduleExpansionPlan) int {
	if e.inParallel || e.prepassDepth > 0 || cap(instanceWorkers) < 2 {
		return 0
	}
	n := 0
	switch plan.mode {
	case expansionCount:
		n = plan.count
	case expansionForEach:
		n = plan.forEach.LengthInt()
	}
	if n < parallelInstancesMin {
		return 0
	}
	return n
}

// instanceWorkers bounds the workers evaluating module instances across the
// process. A worker that cannot get a token is not started; the call's other
// workers, or the caller itself, evaluate its share.
var instanceWorkers = make(chan struct{}, runtime.GOMAXPROCS(0))

// instanceResult is what evaluating one instance of a module call produced.
type instanceResult struct {
	outputs   map[string]cty.Value
	err       error
	resources []ResolvedResource
	// instances are the module calls evaluated inside the instance.
	instances []ModuleInstance
}

// instanceWorker is an evaluator evaluating instances of one module call
// apart from the evaluator that made the call. It shares the parse and path
// caches; everything else it records is merged back when the call is done.
type instanceWorker struct {
	e          *Evaluator
	visiting   map[string]bool
	allVisited *visitSet
}

func (e *Evaluator) newInstanceWorker(visiting map[string]bool) *instanceWorker {
	w := e.Fork()
	w.inParallel = true
	w.canceled = e.canceled
	return &instanceWorker{e: w, visiting: maps.Clone(visiting), allVisited: newVisitSet()}
}

// evaluateInstancesConcurrently evaluates the instances of a module call on
// several workers and returns them, with their results, in instance order.
// Each instance of a call is evaluated independently of the others: its
// inputs are its own, and siblings only see each other through the outputs of
// other calls. So the results, merged in order, are those of evaluating the
// instances one by one. Workers take instances from the plan as they go, so
// nothing is held for instances not yet evaluated.
func (e *Evaluator) evaluateInstancesConcurrently(
	ctx context.Context,
	mb *hclsyntax.Block,
	call *moduleCall,
	plan *moduleExpansionPlan,
	workersWanted int,
	rootDir, addr string,
	childChain []CallSite,
	visiting map[string]bool,
	allVisited *visitSet,
) ([]moduleInstance, []instanceResult) {
	nextInstance, stop := iter.Pull(plan.all)
	defer stop()
	var (
		mu        sync.Mutex
		instances []moduleInstance
		results   []*instanceResult
	)
	// take hands out the next instance and the slot its result goes in.
	take := func(w *instanceWorker) (moduleInstance, *instanceResult, bool) {
		mu.Lock()
		defer mu.Unlock()
		if w.e.stopped() != nil {
			return moduleInstance{}, nil, false
		}
		instance, ok := nextInstance()
		if !ok {
			return moduleInstance{}, nil, false
		}
		r := &instanceResult{}
		instances = append(instances, instance)
		results = append(results, r)
		return instance, r, true
	}
	run := func(w *instanceWorker) {
		for {
			instance, r, ok := take(w)
			if !ok {
				return
			}
			*r = w.evaluate(ctx, mb, call, &instance, rootDir, addr, childChain)
		}
	}
	var workers []*instanceWorker
	var wg sync.WaitGroup
	for range min(cap(instanceWorkers), workersWanted) - 1 {
		select {
		case instanceWorkers <- struct{}{}:
		default:
			continue
		}
		w := e.newInstanceWorker(visiting)
		workers = append(workers, w)
		wg.Go(func() {
			defer func() { <-instanceWorkers }()
			run(w)
		})
	}
	self := e.newInstanceWorker(visiting)
	workers = append(workers, self)
	run(self)
	wg.Wait()
	for _, w := range workers {
		e.absorb(w, allVisited)
	}
	out := make([]instanceResult, len(results))
	for i, r := range results {
		out[i] = *r
	}
	return instances, out
}

// evaluate evaluates one instance into its own result.
func (w *instanceWorker) evaluate(
	ctx context.Context,
	mb *hclsyntax.Block,
	call *moduleCall,
	instance *moduleInstance,
	rootDir, addr string,
	childChain []CallSite,
) instanceResult {
	e := w.e
	if err := e.stopped(); err != nil {
		return instanceResult{err: err}
	}
	modInputs := e.evalBody(mb.Body, instance.ctx, reservedModuleAttrs)
	var r instanceResult
	instancesBefore := len(e.instances)
	r.outputs, r.err = e.evaluate(
		ctx, call.dir, rootDir, call.packageRoot, modInputs, instance.address(addr, call.label),
		childChain, w.visiting, w.allVisited, &r.resources,
	)
	if r.err != nil {
		r.resources = nil
	}
	r.instances = append([]ModuleInstance(nil), e.instances[instancesBefore:]...)
	e.instances = e.instances[:instancesBefore]
	return r
}

// absorb merges what a worker recorded besides its results into e.
func (e *Evaluator) absorb(w *instanceWorker, allVisited *visitSet) {
	we := w.e
	for _, dir := range w.allVisited.order {
		allVisited.add(dir)
	}
	e.report.Merge(&we.report)
	e.skipped += we.skipped
	e.dataBlockEvals += we.dataBlockEvals
	for dir := range we.notEvaluatedDirs {
		e.notEvaluatedDirs[dir] = true
	}
	if we.canceled != nil && e.canceled == nil {
		e.canceled = we.canceled
	}
}
