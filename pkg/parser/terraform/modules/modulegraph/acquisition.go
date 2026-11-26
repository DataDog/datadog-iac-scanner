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

type deferredModuleGroup struct {
	group         *remoteModuleGroup
	status        resolver.RetainedPackageStatus
	reservation   *resolver.AcquisitionLease
	needsPriority bool
}

func (item *deferredModuleGroup) update(status resolver.RetainedPackageStatus) {
	item.status = status
	if status.Reuse || status.Ready != nil && !status.VersionPending {
		// A reusable result or a package with an existing owner needs no
		// claim on acquisition capacity while the selection waits.
		item.reservation.Release()
		item.reservation = nil
	}
	item.needsPriority = item.needsPriority && status.VersionPending
}

func (item *deferredModuleGroup) needsLease() bool {
	return item.reservation == nil && !item.status.Reuse && (item.status.Ready == nil || item.status.VersionPending)
}

type moduleGroupQueue struct {
	ordered  []*remoteModuleGroup
	deferred []deferredModuleGroup
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
	if group := queue.takeReusable(); group != nil {
		start(group, nil)
		return true, nil
	}
	item, index := queue.next()
	if item.group == nil {
		return false, nil
	}
	item.update(lookup(item.group))
	if w.deferExpansion && item.needsLease() {
		lease, changed := w.pollAcquisition()
		switch {
		case queue.earlierSelectionReady(index):
			// A worker changing the budget can also make an earlier
			// selection eligible. Reconsider it before using capacity.
			lease.Release()
			return true, nil
		case changed != nil:
			lease = queue.takeLaterReservation(index)
			if lease == nil {
				queue.waitForAcquisition(index, &item)
				return false, changed
			}
		case lease == nil:
			// Accounting may have finished concurrently with the budget check.
			item.update(lookup(item.group))
		}
		// Later acquisitions may use spare capacity. If the pending version
		// needs a new package, it uses this reservation in its original turn.
		item.reservation = lease
		item.needsPriority = false
	}
	queue.advance(index, &item)
	switch {
	case item.status.Ready != nil:
	case item.status.Reuse || item.reservation != nil || !w.deferExpansion:
		start(item.group, item.reservation)
	default:
		w.recordUnacquiredGroup(item.group)
	}
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
		case <-item.status.Ready:
			item.update(lookup(item.group))
		default:
		}
	}
}

func (q *moduleGroupQueue) takeReusable() *remoteModuleGroup {
	for i, item := range q.deferred {
		if item.status.Reuse {
			q.deferred = slices.Delete(q.deferred, i, i+1)
			return item.group
		}
	}
	return nil
}

func (q *moduleGroupQueue) waitForAcquisition(index int, item *deferredModuleGroup) {
	// Keep the lookup running and preserve its place while it waits for capacity.
	item.needsPriority = item.status.VersionPending
	if index >= 0 {
		q.deferred[index] = *item
	} else if item.needsPriority {
		q.advance(index, item)
	}
}

func (q *moduleGroupQueue) takeLaterReservation(index int) *resolver.AcquisitionLease {
	if index < 0 {
		return nil
	}
	// Hand off the latest idle reservation without exposing its capacity
	// to another frontier. The donor keeps its place when it needs a lease.
	for i := len(q.deferred) - 1; i > index; i-- {
		item := &q.deferred[i]
		if lease := item.reservation; lease != nil {
			item.reservation = nil
			item.needsPriority = item.status.VersionPending
			return lease
		}
	}
	return nil
}

func (q *moduleGroupQueue) next() (item deferredModuleGroup, index int) {
	for i, item := range q.deferred {
		if item.status.Ready == nil || item.needsPriority {
			return item, i
		}
	}
	if len(q.ordered) > 0 {
		return deferredModuleGroup{group: q.ordered[0]}, -1
	}
	return deferredModuleGroup{}, -1
}

func (q *moduleGroupQueue) earlierSelectionReady(index int) bool {
	for i, item := range q.deferred {
		if i == index {
			break
		}
		select {
		case <-item.status.Ready:
			return true
		default:
		}
	}
	return false
}

func (q *moduleGroupQueue) advance(index int, item *deferredModuleGroup) {
	if index >= 0 {
		if item.status.Ready == nil {
			q.deferred = slices.Delete(q.deferred, index, index+1)
		} else {
			q.deferred[index] = *item
		}
		return
	}
	if item.status.Ready != nil {
		q.deferred = append(q.deferred, *item)
	}
	q.ordered = q.ordered[1:]
}

func (q *moduleGroupQueue) fail(w *walker, err error) {
	for _, group := range q.ordered {
		w.recordFailedGroup(group, err)
	}
	for _, item := range q.deferred {
		item.reservation.Release()
		w.recordFailedGroup(item.group, err)
	}
}

// waitForModuleProgress returns true when a worker released its slot. Include
// shared-package signals because their owning workers may be in other frontiers.
func waitForModuleProgress(
	ctx context.Context, completed, budgetChanged <-chan struct{}, waiting []deferredModuleGroup,
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
		if ready := item.status.Ready; ready != nil && !seen[ready] {
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
