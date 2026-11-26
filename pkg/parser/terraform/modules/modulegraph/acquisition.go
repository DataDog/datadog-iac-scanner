/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2026 Datadog, Inc.
 */
package modulegraph

import (
	"context"
	"math"
	"reflect"
	"slices"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
)

type moduleSelectionState uint8

const (
	selectionNeedsAcquisition moduleSelectionState = iota
	selectionVersionNeedsReservation
	selectionVersionReserved
	// The allowance is exhausted. The lookup can still lead to reuse.
	selectionVersionUnreserved
	selectionWaitingForPackage
	selectionReusable
	selectionAcquisitionReserved
	selectionDone
)

func (s moduleSelectionState) ownsReservation() bool {
	return s == selectionVersionReserved || s == selectionAcquisitionReserved
}

// moduleSelection belongs to the frontier until dispatch or cancellation.
// Only the reserved states own capacity. Dispatch transfers it to the worker.
type moduleSelection struct {
	group       *remoteModuleGroup
	state       moduleSelectionState
	ready       <-chan struct{}
	reservation *resolver.AcquisitionLease
}

func (s *moduleSelection) observe(status resolver.RetainedPackageStatus) {
	var next moduleSelectionState
	switch {
	case status.Reuse:
		next = selectionReusable
	case status.Ready == nil:
		next = selectionNeedsAcquisition
		if s.state.ownsReservation() {
			next = selectionAcquisitionReserved
		}
	case !status.VersionPending:
		next = selectionWaitingForPackage
	case s.state.ownsReservation():
		next = selectionVersionReserved
	case s.state == selectionVersionUnreserved || s.state == selectionWaitingForPackage:
		next = selectionVersionUnreserved
	default:
		next = selectionVersionNeedsReservation
	}
	s.transition(next, status.Ready)
}

func (s *moduleSelection) transition(next moduleSelectionState, ready <-chan struct{}) {
	if !next.ownsReservation() {
		s.reservation.Release()
		s.reservation = nil
	}
	s.state, s.ready = next, ready
}

// reserve assigns the result of polling or borrowing capacity. An exhausted
// allowance leaves a pending version lookup eligible for eventual reuse.
func (s *moduleSelection) reserve(lease *resolver.AcquisitionLease) {
	switch {
	case s.state == selectionVersionNeedsReservation && lease != nil:
		s.reservation = lease
		s.transition(selectionVersionReserved, s.ready)
	case s.state == selectionVersionNeedsReservation:
		s.transition(selectionVersionUnreserved, s.ready)
	case lease != nil:
		s.reservation = lease
		s.transition(selectionAcquisitionReserved, nil)
	}
}

func (s *moduleSelection) transfer(next moduleSelectionState, ready <-chan struct{}) *resolver.AcquisitionLease {
	lease := s.reservation
	s.reservation = nil
	s.transition(next, ready)
	return lease
}

func (s *moduleSelection) lendReservation() *resolver.AcquisitionLease {
	switch s.state {
	case selectionVersionReserved:
		return s.transfer(selectionVersionNeedsReservation, s.ready)
	case selectionAcquisitionReserved:
		return s.transfer(selectionNeedsAcquisition, nil)
	default:
		return nil
	}
}

type moduleGroupQueue struct {
	ordered  []*remoteModuleGroup
	deferred []moduleSelection
}

type retainedPackageLookup func(*remoteModuleGroup) resolver.RetainedPackageStatus

// acquireRemoteModuleGroups preserves the order of new acquisitions. Reusable
// results get priority because they need no capacity. Waiting on a package or
// on the budget does not occupy a worker.
func (w *walker) acquireRemoteModuleGroups(
	ctx context.Context,
	groups map[string]*remoteModuleGroup,
	repoAllowedDirs map[string]map[string]bool,
) {
	queue := moduleGroupQueue{ordered: make([]*remoteModuleGroup, 0, len(groups))}
	for _, id := range orderedGroupIDs(groups) {
		queue.ordered = append(queue.ordered, groups[id])
	}
	lookup := func(group *remoteModuleGroup) resolver.RetainedPackageStatus {
		if r, ok := w.resolver.(resolver.RetainedPackageLookup); w.deferExpansion && ok {
			return r.LookupRetainedPackage(ctx, group.representative)
		}
		return resolver.RetainedPackageStatus{}
	}
	limit := max(1, resolver.FetchConcurrency)
	completed := make(chan struct{}, limit)
	running := 0
	start := func(group *remoteModuleGroup, lease *resolver.AcquisitionLease) {
		running++
		go func() {
			defer func() { completed <- struct{}{} }()
			defer lease.Release()
			w.traverseRemoteModuleGroup(ctx, group, repoAllowedDirs, lease)
		}()
	}
	for len(queue.ordered) > 0 || len(queue.deferred) > 0 {
		if err := ctx.Err(); err != nil {
			queue.fail(w, err)
			break
		}
		var budgetChanged <-chan struct{}
		if running < limit {
			var advanced bool
			advanced, budgetChanged = w.scheduleModuleGroup(&queue, lookup, start)
			if advanced {
				continue
			}
		} else {
			// A completed lookup can release a reservation needed by another
			// frontier even when there is no worker available for its selection.
			queue.refreshReady(lookup)
		}
		if waitForModuleProgress(ctx, completed, budgetChanged, queue.deferred) {
			running--
		}
	}
	for ; running > 0; running-- {
		<-completed
	}
}

// scheduleModuleGroup dispatches a ready selection, or advances the next
// group that may need a lease. The budget signal is sampled under its lock.
func (w *walker) scheduleModuleGroup(
	queue *moduleGroupQueue, lookup retainedPackageLookup, start func(*remoteModuleGroup, *resolver.AcquisitionLease),
) (advanced bool, budgetChanged <-chan struct{}) {
	queue.refreshReady(lookup)
	if item := queue.takeReusable(); item != nil {
		start(item, nil)
		return true, nil
	}
	item, index := queue.next()
	if item == nil {
		return false, nil
	}
	item.observe(lookup(item.group))
	if w.deferExpansion && (item.state == selectionNeedsAcquisition || item.state == selectionVersionNeedsReservation) {
		lease, changed := w.pollAcquisition()
		switch {
		case queue.earlierSelectionReady(index):
			// Reconsider the earlier selection before assigning capacity.
			lease.Release()
			return true, nil
		case changed != nil:
			lease = queue.takeLaterReservation(index)
			if lease == nil {
				if index < 0 && item.state == selectionVersionNeedsReservation {
					queue.advance(index, item)
				}
				return false, changed
			}
		case lease == nil:
			// The package may have settled concurrently with the budget check.
			item.observe(lookup(item.group))
		}
		item.reserve(lease)
	}
	switch item.state {
	case selectionReusable, selectionAcquisitionReserved:
		start(item.group, item.transfer(selectionDone, nil))
	case selectionNeedsAcquisition:
		if w.deferExpansion {
			w.recordUnacquiredGroup(item.group)
		} else {
			start(item.group, nil)
		}
		item.transition(selectionDone, nil)
	}
	queue.advance(index, item)
	return true, nil
}

func (w *walker) pollAcquisition() (lease *resolver.AcquisitionLease, changed <-chan struct{}) {
	maximum := w.acquisitionBase + w.acquisitionBytes
	if maximum < w.acquisitionBase {
		maximum = math.MaxInt64
	}
	return w.budget.PollAcquisition(maximum, w.budget.Limits().MaxPackageBytes)
}

func (q *moduleGroupQueue) refreshReady(lookup retainedPackageLookup) {
	for i := range q.deferred {
		item := &q.deferred[i]
		select {
		case <-item.ready:
			item.observe(lookup(item.group))
		default:
		}
	}
}

func (q *moduleGroupQueue) takeReusable() *remoteModuleGroup {
	for i := range q.deferred {
		item := &q.deferred[i]
		if item.state == selectionReusable {
			item.transition(selectionDone, nil)
			group := item.group
			q.advance(i, item)
			return group
		}
	}
	return nil
}

func (q *moduleGroupQueue) takeLaterReservation(index int) *resolver.AcquisitionLease {
	if index < 0 {
		return nil
	}
	// Lend the latest idle reservation without exposing capacity to another
	// frontier. The donor keeps its place when it needs a lease.
	for i := len(q.deferred) - 1; i > index; i-- {
		if lease := q.deferred[i].lendReservation(); lease != nil {
			return lease
		}
	}
	return nil
}

func (q *moduleGroupQueue) next() (selection *moduleSelection, index int) {
	for i := range q.deferred {
		item := &q.deferred[i]
		switch item.state {
		case selectionNeedsAcquisition, selectionVersionNeedsReservation, selectionAcquisitionReserved:
			return item, i
		}
	}
	if len(q.ordered) > 0 {
		return &moduleSelection{group: q.ordered[0]}, -1
	}
	return nil, -1
}

func (q *moduleGroupQueue) earlierSelectionReady(index int) bool {
	for i := range q.deferred {
		if i == index {
			break
		}
		select {
		case <-q.deferred[i].ready:
			return true
		default:
		}
	}
	return false
}

func (q *moduleGroupQueue) advance(index int, item *moduleSelection) {
	if index >= 0 {
		if item.state == selectionDone {
			q.deferred = slices.Delete(q.deferred, index, index+1)
		}
		return
	}
	if item.state != selectionDone {
		q.deferred = append(q.deferred, *item)
	}
	q.ordered = q.ordered[1:]
}

func (q *moduleGroupQueue) fail(w *walker, err error) {
	for _, group := range q.ordered {
		w.recordFailedGroup(group, err)
	}
	for i := range q.deferred {
		item := &q.deferred[i]
		item.transition(selectionDone, nil)
		w.recordFailedGroup(item.group, err)
	}
	q.ordered, q.deferred = nil, nil
}

// waitForModuleProgress returns true when a worker released its slot. Include
// shared-package signals because their owning workers may be in other frontiers.
func waitForModuleProgress(
	ctx context.Context, completed, budgetChanged <-chan struct{}, waiting []moduleSelection,
) bool {
	if len(waiting) == 0 {
		select {
		case <-completed:
			return true
		case <-budgetChanged:
		case <-ctx.Done():
		}
		return false
	}
	cases := []reflect.SelectCase{
		{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(completed)},
		{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(budgetChanged)},
		{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ctx.Done())},
	}
	seen := make(map[<-chan struct{}]bool)
	for _, item := range waiting {
		if ready := item.ready; ready != nil && !seen[ready] {
			seen[ready] = true
			cases = append(cases, reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ready)})
		}
	}
	chosen, _, _ := reflect.Select(cases)
	return chosen == 0
}

func (w *walker) recordFailedGroup(group *remoteModuleGroup, err error) {
	w.results.addModuleStat(moduleStatAborted(group.representative, err))
	for _, mod := range group.callers {
		w.results.addResolutionFailure(mod, group.parentPackageRoot, err)
	}
}
