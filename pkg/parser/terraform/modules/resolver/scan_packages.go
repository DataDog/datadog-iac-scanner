/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2026 Datadog, Inc.
 */
package resolver

import (
	"context"
	"strings"
	"sync"
	"time"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

type scanPackagesKey struct{}

type scanPackageSourceKey struct {
	resolver *GoGetterResolver
	source   string
}

// scanPackage owns one acquisition outcome per resolver, source and concrete
// version. Closing ready publishes the package or its terminal error.
// Successful entries hold a disk-cache pin or temporary extraction and charge
// the graph budget once, before any caller selects a module subdirectory.
type scanPackage struct {
	ready chan struct{}
	res   Resolution
	err   error
}

type scanPackages struct {
	sources  sync.Map // scanPackageSourceKey to *sync.Map of versions
	budget   *ResourceBudget
	versions scanVersionLookups
}

type scanVersionKey struct {
	source     scanPackageSourceKey
	constraint string
}

type scanVersionRequest struct {
	ready      chan struct{}
	version    string
	retryAfter time.Time
}

type scanVersionLookups struct {
	ctx       context.Context
	mu        sync.Mutex
	requests  map[scanVersionKey]*scanVersionRequest
	available chan struct{}
	active    int
	limit     int
	workers   sync.WaitGroup
}

// WithScanPackages shares versioned HTTP acquisitions for one module graph.
// Cleanup releases cache pins and removes temporary extractions after readers
// finish. A package remains charged until then even if every selection fails.
func WithScanPackages(ctx context.Context) (scanCtx context.Context, cleanup func()) {
	versionCtx, cancel := context.WithCancel(ctx)
	packages := &scanPackages{
		budget: ResourceBudgetFromContext(ctx),
		versions: scanVersionLookups{
			ctx: versionCtx, requests: make(map[scanVersionKey]*scanVersionRequest),
			available: make(chan struct{}), limit: max(1, FetchConcurrency),
		},
	}
	return context.WithValue(ctx, scanPackagesKey{}, packages), sync.OnceFunc(func() {
		cancel()
		packages.versions.workers.Wait()
		packages.sources.Range(func(_, versions any) bool {
			versions.(*sync.Map).Range(func(_, value any) bool {
				if cleanup := value.(*scanPackage).res.Cleanup; cleanup != nil {
					cleanup()
				}
				return true
			})
			return true
		})
	})
}

func (l *scanVersionLookups) lookup(
	key scanVersionKey, source string, registry *registryCache,
) (version string, ready <-chan struct{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if request, ok := l.requests[key]; ok {
		select {
		case <-request.ready:
			if request.retryAfter.IsZero() || !registry.clock().After(request.retryAfter) {
				return request.version, nil
			}
		default:
			return "", request.ready
		}
	}
	if l.active >= l.limit {
		return "", l.available
	}
	request := &scanVersionRequest{ready: make(chan struct{})}
	l.requests[key] = request
	l.active++
	l.workers.Add(1)
	go func() {
		defer l.workers.Done()
		var err error
		request.version, err = registry.resolveConcreteVersion(l.ctx, source, key.constraint)
		if err != nil {
			request.retryAfter = registry.clock().Add(registry.failureBackoff())
		}
		close(request.ready)
		l.mu.Lock()
		l.active--
		close(l.available)
		l.available = make(chan struct{})
		l.mu.Unlock()
	}()
	return "", request.ready
}

func (r *GoGetterResolver) LookupRetainedPackage(ctx context.Context, mod *tfmodules.ParsedModule) RetainedPackageStatus {
	packages, ok := ctx.Value(scanPackagesKey{}).(*scanPackages)
	if !ok || ctx.Err() != nil {
		return RetainedPackageStatus{}
	}
	key := scanPackageSourceKey{resolver: r, source: canonicalizeModuleCacheSource(mod.Source)}
	versions, ok := packages.sources.Load(key)
	if !ok || r.Screen(ctx, mod) != nil {
		return RetainedPackageStatus{}
	}
	version := mod.Version
	if sourceType, _ := tfmodules.DetectModuleSourceType(mod.Source); sourceType == sourceTypeRegistry {
		var ready <-chan struct{}
		if v, cached := r.cfg.RegistryCache.cachedConcreteVersion(mod.Source, version); cached {
			version = v
		} else {
			versionKey := scanVersionKey{source: key, constraint: mod.Version}
			version, ready = packages.versions.lookup(versionKey, mod.Source, r.cfg.RegistryCache)
		}
		if ready != nil {
			return RetainedPackageStatus{Ready: ready, VersionPending: true}
		}
	}
	value, ok := versions.(*sync.Map).Load(strings.TrimSpace(version))
	if !ok {
		return RetainedPackageStatus{}
	}
	entry := value.(*scanPackage)
	return entry.reuseStatus(packages.budget)
}

func (entry *scanPackage) reuseStatus(budget *ResourceBudget) RetainedPackageStatus {
	select {
	case <-entry.ready:
		// A settled error can also be returned without another lease.
		return RetainedPackageStatus{Reuse: entry.err != nil || entry.res.ChargedTo(budget)}
	default:
		return RetainedPackageStatus{Ready: entry.ready}
	}
}

func (r *GoGetterResolver) resolveScanPackage(
	ctx context.Context, packages *scanPackages, mod *tfmodules.ParsedModule,
	getterSource, sourceType, version, subdir string, useCache bool,
) (Resolution, error) {
	key := scanPackageSourceKey{resolver: r, source: canonicalizeModuleCacheSource(mod.Source)}
	versions, _ := packages.sources.LoadOrStore(key, &sync.Map{})
	value, loaded := versions.(*sync.Map).LoadOrStore(strings.TrimSpace(version), &scanPackage{ready: make(chan struct{})})
	entry := value.(*scanPackage)
	if loaded {
		select {
		case <-entry.ready:
		case <-ctx.Done():
			return Resolution{}, ctx.Err()
		}
	} else {
		res, hit, err := r.lookupCache(ctx, mod, version, "", useCache)
		state := CacheStateHit
		if err == nil && !hit {
			packageSource, _ := splitGetterSubdir(getterSource)
			res, err = r.fetchPackage(ctx, mod, packageSource, version, subdir, "", useCache)
			state = ""
			if useCache {
				state = CacheStateMiss
			}
		}
		if err == nil && packages.budget != nil {
			res, err = packages.accountPackage(ctx, &res)
		}
		labelResolution(&res, sourceType, state)
		entry.res, entry.err = res, err
		close(entry.ready)
	}
	res, err := entry.selectModule(ctx, subdir)
	if err != nil {
		return Resolution{}, err
	}
	if sourceType == sourceTypeRegistry {
		res.registryArchiveSubdir = subdir
	}
	return stampRegistryResolution(&res, sourceType, version, getterSource), nil
}

// selectModule returns the caller's view of the acquired package. Selection
// errors are specific to that caller and the returned view owns no cleanup.
func (entry *scanPackage) selectModule(ctx context.Context, subdir string) (Resolution, error) {
	if entry.err != nil {
		return Resolution{}, entry.err
	}
	res, err := resolutionForPackage(ctx, entry.res.PackageRoot, subdir)
	if err != nil {
		return Resolution{}, &tfmodules.UnresolvedError{Reason: "invalid acquired module package: " + err.Error()}
	}
	res.Origin, res.Cache = entry.res.Origin, entry.res.Cache
	res.Usage = entry.res.Usage
	res.chargedBudget = entry.res.chargedBudget
	return res, nil
}

func (p *scanPackages) accountPackage(ctx context.Context, res *Resolution) (Resolution, error) {
	usage, err := MeasurePackage(ctx, res.PackageRoot, ResourceBudgetFromContext(ctx).Limits())
	if err == nil {
		err = p.budget.AdmitPackage(res.PackageRoot, usage)
	}
	if err != nil {
		res.Cleanup()
		return Resolution{}, unresolvedResourceError(err)
	}
	// Charge the retained extraction before the worker releases its lease,
	// even if none of its callers can select a subdirectory.
	res.Usage = &usage
	res.chargedBudget = p.budget
	return *res, nil
}
