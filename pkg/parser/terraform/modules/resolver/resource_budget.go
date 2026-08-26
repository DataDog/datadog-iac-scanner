/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sync"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

// limitPackageBytes names the per-package byte limit in budget events.
const limitPackageBytes = "package_bytes"

const (
	DefaultMaxPackageBytes = 128 * 1024 * 1024
	DefaultMaxFileBytes    = 5 * 1024 * 1024
	DefaultMaxPackageFiles = 10_000
)

type ResourceLimits struct {
	MaxPackageBytes int64
	MaxFileBytes    int64
	MaxPackageFiles int
	MaxTotalBytes   int64
}

func (l ResourceLimits) Enabled() bool {
	return l.MaxPackageBytes > 0 || l.MaxFileBytes > 0 || l.MaxPackageFiles > 0 || l.MaxTotalBytes > 0
}

type PackageUsage struct {
	Bytes int64
	Files int
}

type BudgetExceededError struct {
	Gate     string
	Limit    string
	Maximum  int64
	Measured int64
}

func (e *BudgetExceededError) Error() string {
	return fmt.Sprintf(
		"module resource budget exceeded at %s: %s limit %d, measured %d",
		e.Gate, e.Limit, e.Maximum, e.Measured,
	)
}

func unresolvedResourceError(err error) error {
	var budgetErr *BudgetExceededError
	if errors.As(err, &budgetErr) {
		return budgetErr
	}
	return &tfmodules.UnresolvedError{Reason: err.Error()}
}

type resourceBudgetContextKey struct{}

type ResourceBudget struct {
	limits ResourceLimits

	mu                  sync.Mutex
	packages            map[string]PackageUsage
	total               PackageUsage
	acquisitionReserved int64
	acquisitionChanged  chan struct{}
}

func NewResourceBudget(limits ResourceLimits) *ResourceBudget {
	return &ResourceBudget{
		limits:             limits,
		packages:           make(map[string]PackageUsage),
		acquisitionChanged: make(chan struct{}),
	}
}

type AcquisitionLease struct {
	budget *ResourceBudget
	bytes  int64
	once   sync.Once
}

func (l *AcquisitionLease) Bytes() int64 {
	if l == nil {
		return 0
	}
	return l.bytes
}

func (l *AcquisitionLease) Release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		l.budget.releaseAcquisition(l.bytes)
	})
}

func WithResourceBudget(ctx context.Context, budget *ResourceBudget) context.Context {
	if budget == nil {
		return ctx
	}
	return context.WithValue(ctx, resourceBudgetContextKey{}, budget)
}

func ResourceBudgetFromContext(ctx context.Context) *ResourceBudget {
	if ctx == nil {
		return nil
	}
	budget, _ := ctx.Value(resourceBudgetContextKey{}).(*ResourceBudget)
	return budget
}

func (b *ResourceBudget) Limits() ResourceLimits {
	if b == nil {
		return ResourceLimits{}
	}
	return b.limits
}

func (b *ResourceBudget) NewPackageCounter() *PackageCounter {
	if b == nil {
		return &PackageCounter{}
	}
	return &PackageCounter{limits: b.limits}
}

func (b *ResourceBudget) AdmitPackage(identity string, usage PackageUsage) error {
	if b == nil {
		return nil
	}
	identity = filepath.Clean(identity)

	b.mu.Lock()
	defer b.mu.Unlock()
	if previous, exists := b.packages[identity]; exists {
		b.total.Bytes -= previous.Bytes
		b.total.Files -= previous.Files
		usage.Bytes = max(usage.Bytes, previous.Bytes)
		usage.Files = max(usage.Files, previous.Files)
	}
	b.packages[identity] = usage
	b.total.Bytes += usage.Bytes
	b.total.Files += usage.Files
	b.notifyAcquisitionChangedLocked()
	return nil
}

func (b *ResourceBudget) TryAcquireAcquisition(maximum, requested int64) (*AcquisitionLease, bool) {
	if b == nil || maximum <= 0 {
		return nil, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tryAcquireAcquisitionLocked(maximum, requested)
}

func (b *ResourceBudget) AcquireAcquisition(
	ctx context.Context, maximum, requested int64,
) (*AcquisitionLease, bool) {
	if b == nil || maximum <= 0 {
		return nil, false
	}
	for {
		b.mu.Lock()
		if lease, ok := b.tryAcquireAcquisitionLocked(maximum, requested); ok {
			b.mu.Unlock()
			return lease, true
		}
		if b.total.Bytes >= maximum {
			b.mu.Unlock()
			return nil, false
		}
		if b.acquisitionChanged == nil {
			b.acquisitionChanged = make(chan struct{})
		}
		changed := b.acquisitionChanged
		b.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, false
		case <-changed:
		}
	}
}

func (b *ResourceBudget) tryAcquireAcquisitionLocked(
	maximum, requested int64,
) (*AcquisitionLease, bool) {
	available := maximum - b.total.Bytes - b.acquisitionReserved
	if available <= 0 {
		return nil, false
	}
	if requested <= 0 || requested > available {
		requested = available
	}
	b.acquisitionReserved += requested
	return &AcquisitionLease{budget: b, bytes: requested}, true
}

func (b *ResourceBudget) releaseAcquisition(reserved int64) {
	if b == nil || reserved <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.acquisitionReserved -= reserved
	b.notifyAcquisitionChangedLocked()
}

func (b *ResourceBudget) notifyAcquisitionChangedLocked() {
	if b.acquisitionChanged == nil {
		b.acquisitionChanged = make(chan struct{})
		return
	}
	close(b.acquisitionChanged)
	b.acquisitionChanged = make(chan struct{})
}

func (b *ResourceBudget) Usage(identity string) (PackageUsage, bool) {
	if b == nil {
		return PackageUsage{}, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	usage, ok := b.packages[filepath.Clean(identity)]
	return usage, ok
}

func (b *ResourceBudget) TotalUsage() PackageUsage {
	if b == nil {
		return PackageUsage{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.total
}

type PackageCounter struct {
	limits ResourceLimits
	usage  PackageUsage
}

type packageTreeCounter struct {
	counter *PackageCounter
	dirs    map[string]bool
}

func newPackageTreeCounter(counter *PackageCounter) *packageTreeCounter {
	return &packageTreeCounter{counter: counter, dirs: make(map[string]bool)}
}

func (c *packageTreeCounter) addDir(name string) error {
	name = filepath.Clean(name)
	if name == "." || name == string(filepath.Separator) || c.dirs[name] {
		return nil
	}
	if parent := filepath.Dir(name); parent != name {
		if err := c.addDir(parent); err != nil {
			return err
		}
	}
	c.dirs[name] = true
	return c.counter.AddEntry(0)
}

func (c *PackageCounter) AddEntry(size int64) error {
	if size < 0 {
		return errors.New("module file size cannot be negative")
	}
	if c.limits.MaxFileBytes > 0 && size > c.limits.MaxFileBytes {
		return &BudgetExceededError{
			Gate:     "stream",
			Limit:    "file_bytes",
			Maximum:  c.limits.MaxFileBytes,
			Measured: size,
		}
	}
	files := c.usage.Files + 1
	if c.limits.MaxPackageFiles > 0 && files > c.limits.MaxPackageFiles {
		return &BudgetExceededError{
			Gate:     "stream",
			Limit:    "package_file_count",
			Maximum:  int64(c.limits.MaxPackageFiles),
			Measured: int64(files),
		}
	}
	bytes := c.usage.Bytes + size
	if c.limits.MaxPackageBytes > 0 && bytes > c.limits.MaxPackageBytes {
		return &BudgetExceededError{
			Gate:     "stream",
			Limit:    limitPackageBytes,
			Maximum:  c.limits.MaxPackageBytes,
			Measured: bytes,
		}
	}
	c.usage = PackageUsage{Bytes: bytes, Files: files}
	return nil
}

func (c *PackageCounter) Usage() PackageUsage {
	if c == nil {
		return PackageUsage{}
	}
	return c.usage
}

func MeasurePackage(ctx context.Context, root string, limits ResourceLimits) (PackageUsage, error) {
	// Per-file limits apply while bytes are streaming; packages already on disk may
	// contain large artifacts such as lambda zips or generated policies.
	measureLimits := limits
	measureLimits.MaxFileBytes = 0

	counter := (&ResourceBudget{limits: measureLimits}).NewPackageCounter()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			if filepath.Clean(path) != filepath.Clean(root) {
				return counter.AddEntry(0)
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		return counter.AddEntry(info.Size())
	})
	if err != nil {
		return PackageUsage{}, err
	}
	return counter.Usage(), nil
}
