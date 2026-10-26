/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"math"
	"runtime/debug"
	"sync"

	"github.com/zclconf/go-cty/cty"
)

const (
	// minMemoizedSize is the input size from which a repeated call costs more
	// than remembering it.
	minMemoizedSize = 4 << 10
	// defaultScanBudget is the estimated memory the results kept by one
	// ScanFS may use when the process has no memory limit to scale it from.
	defaultScanBudget = 768 << 20
	// minScanBudget and maxScanBudget bound the share of a memory limit that
	// one ScanFS's kept results may use.
	minScanBudget = 256 << 20
	maxScanBudget = 4 << 30
	// memoryLimitShare is the fraction of the process memory limit the
	// results kept by one ScanFS may use.
	memoryLimitShare = 4
	// kindShare is the fraction of a ScanFS budget each kind of result may
	// use on its own; the kinds share the rest for results that do not fit.
	kindShare = 8
	// maxSeen bounds the keys remembered as computed once. Reaching it starts
	// the record over, so a scan computing a new input per call does not grow
	// a record per call.
	maxSeen = 1 << 17
	// maxRefused bounds keys refused for size or budget across seen resets.
	maxRefused = 1 << 17
)

// scanBudget is the estimated memory all ScanFS memos in the process may keep
// together: a quarter of the memory limit within its bounds, or 768 MiB
// without a limit. Each memo keeps an eighth of it within its own budget, and
// the memos share the rest for results larger than what is left of their own.
func scanBudget() int {
	limit := debug.SetMemoryLimit(-1)
	if limit == math.MaxInt64 {
		return defaultScanBudget
	}
	return int(min(max(limit/memoryLimitShare, minScanBudget), maxScanBudget))
}

// processRetained is the memory every ScanFS memo in the process may keep in
// total, so concurrent ScanFS share one quarter rather than each taking one.
var (
	processRetainedMu  sync.Mutex
	processRetainedAll *allowance
)

func processRetained() *allowance {
	processRetainedMu.Lock()
	defer processRetainedMu.Unlock()
	total := scanBudget()
	if processRetainedAll == nil {
		processRetainedAll = &allowance{size: total}
	} else if total > processRetainedAll.size {
		processRetainedAll.size = total
	}
	return processRetainedAll
}

// allowance is the memory memos share for kept results.
type allowance struct {
	mu         sync.Mutex
	used, size int
}

func (a *allowance) take(n int) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.used+n > a.size {
		return false
	}
	a.used += n
	return true
}

func (a *allowance) release(n int) {
	a.mu.Lock()
	a.used -= n
	if a.used < 0 {
		a.used = 0
	}
	a.mu.Unlock()
}

// resultMemo shares the results of calls asked for again. Every instance of a
// module loop, every root and every reparse of a file calls its functions
// again, so a loop reading one large configuration file would read, decode or
// parse it once per call. cty values and parsed templates are immutable, so a
// result asked for more than once is kept and shared for the rest of the
// scan, and a result used once dies with the call that used it.
//
// Kept results are never evicted to make room: under the cyclic access of a
// module loop, eviction would drop each one just before it is asked for
// again. Results larger than what is left of the budget are kept from the
// allowance shared by every ScanFS in the process, so the few large
// configurations a scan shares are each computed a fixed number of times
// whatever their size.
//
// pending collapses concurrent computations of one key: roots are evaluated in
// parallel, and each would otherwise build its own copy at the same time.
type resultMemo[K comparable, R any] struct {
	mu     sync.Mutex
	budget int
	large  *allowance
	// estimate returns the memory a result keeps live, or false for a result
	// not worth keeping.
	estimate func(K, R) (int, bool)
	// kept runs under mu when a result is kept.
	kept func(R)

	entries map[K]R
	size    int
	// retained is bytes taken from large for entries still held.
	retained int
	// seen holds every key computed, true once its result was measured and
	// not kept, so asking again does not measure it again.
	seen map[K]bool
	// refused holds keys that did not fit the budget; it survives seen resets.
	refused map[K]struct{}
	pending map[K]*pendingResult[R]
}

type pendingResult[R any] struct {
	done    chan struct{}
	result  R
	ok      bool
	waiters int
}

func newResultMemo[K comparable, R any](budget int, large *allowance, estimate func(K, R) (int, bool)) *resultMemo[K, R] {
	return &resultMemo[K, R]{
		budget:   budget,
		large:    large,
		estimate: estimate,
		entries:  map[K]R{},
		seen:     map[K]bool{},
		refused:  map[K]struct{}{},
		pending:  map[K]*pendingResult[R]{},
	}
}

// lookupOrCompute returns the kept result of key, or computes it once however
// many callers ask for it at the same time. A caller waiting on that
// computation, or a key computed before, makes the result worth keeping.
func (m *resultMemo[K, R]) lookupOrCompute(key K, compute func() R) R {
	m.mu.Lock()
	if kept, ok := m.entries[key]; ok {
		m.mu.Unlock()
		return kept
	}
	if p, ok := m.pending[key]; ok {
		p.waiters++
		m.mu.Unlock()
		<-p.done
		if p.ok {
			return p.result
		}
		return compute()
	}
	_, refused := m.refused[key]
	rejected, repeated := m.seen[key]
	rejected = rejected || refused
	if !repeated {
		if len(m.seen) >= maxSeen {
			m.seen = map[K]bool{}
		}
		m.seen[key] = false
	}
	p := &pendingResult[R]{done: make(chan struct{})}
	m.pending[key] = p
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		wanted := p.ok && !rejected && (repeated || p.waiters > 0)
		m.mu.Unlock()
		size, worth := 0, false
		if wanted {
			size, worth = m.estimate(key, p.result)
		}
		m.mu.Lock()
		switch {
		case worth:
			m.remember(key, p.result, size)
		case wanted:
			m.seen[key] = true
		}
		delete(m.pending, key)
		m.mu.Unlock()
		close(p.done)
	}()
	p.result = compute()
	p.ok = true
	return p.result
}

// forget drops key from seen so a later call can be measured again.
func (m *resultMemo[K, R]) forget(key K) {
	m.mu.Lock()
	delete(m.seen, key)
	m.mu.Unlock()
}

// releaseAll drops kept results and returns their charge to large.
func (m *resultMemo[K, R]) releaseAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.retained > 0 {
		m.large.release(m.retained)
		m.retained = 0
	}
	m.entries = map[K]R{}
	m.seen = map[K]bool{}
	m.size = 0
	m.pending = map[K]*pendingResult[R]{}
}

// remember keeps result if it fits what is left of the budget, or else what
// is left of the shared allowance. It runs under mu. Production memos share
// processRetained so every keep charges one process quarter; a local
// allowance (tests) keeps the kind-then-large split.
func (m *resultMemo[K, R]) remember(key K, result R, size int) {
	if m.large == processRetained() {
		if !m.large.take(size) {
			m.markRefused(key)
			return
		}
		m.retained += size
		if m.size+size <= m.budget {
			m.size += size
		}
	} else {
		switch {
		case m.size+size <= m.budget:
			m.size += size
		case m.large.take(size):
		default:
			m.markRefused(key)
			return
		}
	}
	m.entries[key] = result
	if m.kept != nil {
		m.kept(result)
	}
}

func (m *resultMemo[K, R]) markRefused(key K) {
	// A full set keeps the marks it has. Replacing it would decode those
	// values again, which is what the set is there to avoid.
	if len(m.refused) < maxRefused {
		m.refused[key] = struct{}{}
	}
	m.seen[key] = true
}

// Estimates, in bytes, of what each part of a kept result keeps live,
// measured on JSON and YAML documents and on templates of each shape.
const (
	retainedScalar  = 32
	retainedNumber  = 80
	retainedString  = 32
	retainedTuple   = 64
	retainedElement = 32
	retainedObject  = 512
	retainedAttr    = 192
	retainedError   = 256
	retainedEntry   = 256
	retainedNode    = 144
)

func estimateError(err error) int {
	return retainedError + len(err.Error())
}

func estimateValue(v cty.Value) int {
	ty := v.Type()
	switch {
	case !v.IsKnown() || v.IsNull():
		return retainedScalar
	case ty == cty.String:
		return retainedString + len(v.AsString())
	case ty == cty.Number:
		return retainedNumber
	case ty.IsObjectType():
		n := retainedObject
		for name := range ty.AttributeTypes() {
			n += retainedAttr + 2*len(name) + estimateValue(v.GetAttr(name))
		}
		return n
	case ty.IsCollectionType() || ty.IsTupleType():
		n := retainedTuple
		for it := v.ElementIterator(); it.Next(); {
			k, e := it.Element()
			n += retainedElement + estimateValue(e)
			if ty.IsMapType() {
				n += 2 * len(k.AsString())
			}
		}
		return n
	}
	return retainedScalar
}
