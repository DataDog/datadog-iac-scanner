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
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	getter "github.com/hashicorp/go-getter"
	"golang.org/x/sync/singleflight"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

const (
	DefaultFetchTimeout   = 30 * time.Second
	DefaultMaxModuleBytes = 0
	DefaultMaxTotalBytes  = 200 * 1024 * 1024
	mib                   = 1024 * 1024

	sourceTypeRegistry = "registry"
	sourceTypeGit      = "git"

	defaultFetchConcurrency = 32 // network-bound; override via IAC_MODULE_FETCH_CONCURRENCY
)

// FetchConcurrency bounds simultaneous go-getter downloads (IAC_MODULE_FETCH_CONCURRENCY).
var FetchConcurrency = fetchConcurrencyFromEnv()

func fetchConcurrencyFromEnv() int {
	if v := os.Getenv("IAC_MODULE_FETCH_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultFetchConcurrency
}

const defaultHostFetchConcurrency = 6 // per-host cap; override via IAC_MODULE_HOST_FETCH_CONCURRENCY

var HostFetchConcurrency = hostFetchConcurrencyFromEnv()

func hostFetchConcurrencyFromEnv() int {
	if v := os.Getenv("IAC_MODULE_HOST_FETCH_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return defaultHostFetchConcurrency
}

// GoGetterConfig holds caps and options for GoGetterResolver.
// It must not be copied after first use (contains atomic.Int64 and a channel); always use a pointer.
type GoGetterConfig struct {
	Disabled bool

	FetchTimeout time.Duration
	// MaxModuleBytes caps each individual module fetch when no graph budget is attached.
	MaxModuleBytes int64
	// MaxTotalBytes is retained for standalone resolver compatibility.
	MaxTotalBytes int64

	HostAllowlist []string
	Cache         *moduleCache
	RegistryCache *registryCache
	// Git resolves pinnable git:: download URLs (registry X-Terraform-Get and
	// default-branch sources) through BareGit instead of an unpinned git subprocess.
	Git        Resolver
	httpClient *http.Client

	TmpDir string

	totalBytesUsed atomic.Int64
	fetchSem       chan struct{}
	accountedDirs  sync.Map

	hostSems   sync.Map
	resolveSF  singleflight.Group
	fetchCount atomic.Int64
}

// NewGoGetterConfig returns default fetch limits and concurrency controls.
func NewGoGetterConfig() *GoGetterConfig {
	return &GoGetterConfig{
		FetchTimeout:   DefaultFetchTimeout,
		MaxModuleBytes: DefaultMaxModuleBytes,
		MaxTotalBytes:  DefaultMaxTotalBytes,
		fetchSem:       make(chan struct{}, FetchConcurrency),
	}
}

// GoGetterResolver downloads modules via hashicorp/go-getter (registry translation, caps, cache).
type GoGetterResolver struct {
	cfg *GoGetterConfig
}

func NewGoGetterResolver(cfg *GoGetterConfig) *GoGetterResolver {
	if cfg.httpClient == nil {
		cfg.httpClient = newPolicyHTTPClient(cfg.FetchTimeout, cfg.HostAllowlist)
	}
	cfg.httpClient = withResourceBudgetTransport(cfg.httpClient, cfg.MaxModuleBytes)
	if cfg.RegistryCache == nil {
		cfg.RegistryCache = NewRegistryCache(cfg.FetchTimeout, cfg.HostAllowlist...)
	}
	return &GoGetterResolver{cfg: cfg}
}

func (r *GoGetterResolver) Resolve(ctx context.Context, mod *tfmodules.ParsedModule) (Resolution, error) {
	if r.cfg.Disabled {
		return Resolution{}, &tfmodules.UnresolvedError{
			Reason: "remote module fetching is disabled; run terraform init or pass --modules-manifest",
		}
	}
	if mod.IsLocal {
		return Resolution{}, &tfmodules.UnresolvedError{Reason: "local modules are handled by LocalResolver"}
	}
	// BareGit owns pinnable git:: sources. Falling through after a BareGit failure
	// would trigger a full working-tree clone of the entire repository per module.
	if bareGitOwnsSource(mod.Source) {
		return Resolution{}, &tfmodules.UnresolvedError{
			Reason: "git module with ref= must be resolved by BareGitResolver (go-getter fallback disabled)",
		}
	}
	if err := r.checkAllowlist(mod.Source); err != nil {
		return Resolution{}, err
	}

	st, _ := tfmodules.DetectModuleSourceType(mod.Source)
	cacheVersion, err := r.resolveCacheVersion(ctx, st, mod)
	if err != nil {
		return Resolution{}, err
	}

	useCache := r.cfg.Cache != nil && cacheableModule(mod.Source, cacheVersion)
	getterSrc, err := r.getterSourceFor(ctx, st, mod, cacheVersion)
	if err != nil {
		return Resolution{}, err
	}
	_, selectedSubdir := splitGetterSubdir(getterSrc)
	if selectedSubdir == "" && st == sourceTypeRegistry {
		selectedSubdir = registrySubdir(mod.Source)
	}
	if res, ok, cacheErr := r.lookupCache(ctx, mod, cacheVersion, selectedSubdir, useCache); cacheErr != nil {
		return Resolution{}, cacheErr
	} else if ok {
		return res, nil
	}

	// Coalesce cacheable fetches; non-cacheable results carry per-call Cleanup.
	if useCache {
		key := moduleCacheKey(mod.Source, cacheVersion)
		v, sfErr, _ := r.cfg.resolveSF.Do(key, func() (interface{}, error) {
			return r.fetchAndCommit(ctx, st, mod, cacheVersion, selectedSubdir, useCache)
		})
		if sfErr != nil {
			return Resolution{}, sfErr
		}
		return v.(Resolution), nil
	}
	return r.fetchAndCommit(ctx, st, mod, cacheVersion, selectedSubdir, useCache)
}

func (r *GoGetterResolver) fetchAndCommit(
	ctx context.Context, sourceType string, mod *tfmodules.ParsedModule, cacheVersion, selectedSubdir string, useCache bool,
) (Resolution, error) {
	getterSrc, err := r.getterSourceFor(ctx, sourceType, mod, cacheVersion)
	if err != nil {
		return Resolution{}, err
	}
	packageSource, parsedSubdir := splitGetterSubdir(getterSrc)
	if selectedSubdir == "" {
		selectedSubdir = parsedSubdir
	}
	if selectedSubdir == "" && sourceType == sourceTypeRegistry {
		selectedSubdir = registrySubdir(mod.Source)
	}
	if gitMod, ok := pinnableGitModuleFromGetterSource(packageSource, selectedSubdir); ok {
		if r.cfg.Git == nil {
			return Resolution{}, &tfmodules.UnresolvedError{
				Reason: "pinned git download must be resolved by BareGitResolver",
			}
		}
		if err := r.checkAllowlist(packageSource); err != nil {
			return Resolution{}, err
		}
		return r.cfg.Git.Resolve(ctx, gitMod)
	}
	if err := validateGetterSourceTransport(packageSource); err != nil {
		return Resolution{}, err
	}
	if err := r.checkAllowlist(packageSource); err != nil {
		return Resolution{}, err
	}
	// Per-host slot before global slot so one saturated host cannot starve others.
	releaseHost, err := r.acquireHostSlot(ctx, extractSourceHost(packageSource))
	if err != nil {
		return Resolution{}, err
	}
	defer releaseHost()
	if err := r.acquireFetchSlot(ctx); err != nil {
		return Resolution{}, err
	}
	defer r.releaseFetchSlot()

	if res, ok, cacheErr := r.lookupCache(ctx, mod, cacheVersion, selectedSubdir, useCache); cacheErr != nil {
		return Resolution{}, cacheErr
	} else if ok {
		return res, nil
	}

	tmpDir, err := r.fetch(ctx, packageSource)
	if err != nil {
		return Resolution{}, err
	}
	return r.commitFetchedDir(ctx, mod.Source, cacheVersion, tmpDir, selectedSubdir, useCache)
}

func (r *GoGetterResolver) resolveCacheVersion(
	ctx context.Context, sourceType string, mod *tfmodules.ParsedModule,
) (string, error) {
	if sourceType == sourceTypeRegistry {
		return r.cfg.RegistryCache.resolveConcreteVersion(ctx, mod.Source, mod.Version)
	}
	return mod.Version, nil
}

func (r *GoGetterResolver) getterSourceFor(
	ctx context.Context, sourceType string, mod *tfmodules.ParsedModule, cacheVersion string,
) (string, error) {
	if sourceType == sourceTypeRegistry {
		dlURL, err := r.cfg.RegistryCache.resolveGetterURL(ctx, mod.Source, cacheVersion)
		if err != nil {
			return "", err
		}
		return withDepth(dlURL), nil
	}
	src := mod.Source
	if normalized, ok := normalizeGitModuleSourceForGetter(src); ok {
		src = normalized
	}
	return withDepth(src), nil
}

func (r *GoGetterResolver) lookupCache(
	ctx context.Context, mod *tfmodules.ParsedModule, cacheVersion, selectedSubdir string, useCache bool,
) (Resolution, bool, error) {
	if !useCache {
		return Resolution{}, false, nil
	}
	packageRoot, ok := r.cfg.Cache.lookup(mod.Source, cacheVersion)
	if !ok {
		return Resolution{}, false, nil
	}
	if ResourceBudgetFromContext(ctx) == nil {
		if err := r.reserveDirBytes(ctx, packageRoot); err != nil {
			return Resolution{}, false, err
		}
	}
	resolution, err := resolutionForPackage(ctx, packageRoot, selectedSubdir)
	if err != nil {
		return Resolution{}, false, &tfmodules.UnresolvedError{Reason: "invalid cached module package: " + err.Error()}
	}
	return resolution, true, nil
}

func (r *GoGetterResolver) checkByteLimits(size int64) error {
	if r.cfg.MaxModuleBytes > 0 && size > r.cfg.MaxModuleBytes {
		return &tfmodules.UnresolvedError{
			Reason: fmt.Sprintf("module exceeds per-module limit of %d MiB", r.cfg.MaxModuleBytes/mib),
		}
	}
	if r.cfg.MaxTotalBytes > 0 {
		if used := r.cfg.totalBytesUsed.Add(size); used > r.cfg.MaxTotalBytes {
			r.cfg.totalBytesUsed.Add(-size)
			return &tfmodules.UnresolvedError{Reason: "scan-level remote module byte cap exceeded"}
		}
	}
	return nil
}

func (r *GoGetterResolver) reserveDirBytes(ctx context.Context, dir string) error {
	cleanDir := filepath.Clean(dir)
	if _, loaded := r.cfg.accountedDirs.LoadOrStore(cleanDir, struct{}{}); loaded {
		return nil
	}
	usage, err := MeasurePackage(ctx, dir, ResourceLimits{})
	if err != nil {
		r.cfg.accountedDirs.Delete(cleanDir)
		return &tfmodules.UnresolvedError{Reason: "measuring cached module: " + err.Error()}
	}
	if err := r.checkByteLimits(usage.Bytes); err != nil {
		r.cfg.accountedDirs.Delete(cleanDir)
		return err
	}
	return nil
}

func (r *GoGetterResolver) acquireFetchSlot(ctx context.Context) error {
	sem := r.cfg.fetchSem
	if sem == nil {
		return nil
	}
	select {
	case sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return &tfmodules.UnresolvedError{Reason: "context canceled waiting for fetch slot"}
	}
}

func (r *GoGetterResolver) releaseFetchSlot() {
	if r.cfg.fetchSem != nil {
		<-r.cfg.fetchSem
	}
}

func (r *GoGetterResolver) acquireHostSlot(ctx context.Context, host string) (func(), error) {
	if HostFetchConcurrency <= 0 || host == "" {
		return func() {}, nil
	}
	v, _ := r.cfg.hostSems.LoadOrStore(host, make(chan struct{}, HostFetchConcurrency))
	sem := v.(chan struct{})
	select {
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	case <-ctx.Done():
		return nil, &tfmodules.UnresolvedError{Reason: "context canceled waiting for host fetch slot"}
	}
}

// commitFetchedDir caches the fetched package and returns its selected module.
func (r *GoGetterResolver) commitFetchedDir(
	ctx context.Context, source, version, tmpDir, selectedSubdir string, useCache bool,
) (Resolution, error) {
	if ResourceBudgetFromContext(ctx) == nil {
		usage, err := MeasurePackage(ctx, tmpDir, ResourceLimits{})
		if err != nil {
			_ = os.RemoveAll(tmpDir)
			return Resolution{}, &tfmodules.UnresolvedError{Reason: "measuring module size: " + err.Error()}
		}
		if err := r.checkByteLimits(usage.Bytes); err != nil {
			_ = os.RemoveAll(tmpDir)
			return Resolution{}, err
		}
	}
	if useCache {
		if cached, storeErr := r.cfg.Cache.store(source, version, tmpDir, selectedSubdir); storeErr == nil {
			_ = os.RemoveAll(tmpDir)
			if ResourceBudgetFromContext(ctx) == nil {
				r.cfg.accountedDirs.Store(filepath.Clean(cached), struct{}{})
			}
			resolution, err := resolutionForPackage(ctx, cached, selectedSubdir)
			if err != nil {
				return Resolution{}, &tfmodules.UnresolvedError{Reason: "invalid cached module package: " + err.Error()}
			}
			return resolution, nil
		}
	}
	cleanup := func() { _ = os.RemoveAll(tmpDir) }
	resolution, err := resolutionForPackage(ctx, tmpDir, selectedSubdir)
	if err != nil {
		cleanup()
		return Resolution{}, &tfmodules.UnresolvedError{Reason: "invalid fetched module package: " + err.Error()}
	}
	resolution.Cleanup = cleanup
	return resolution, nil
}

func resolutionForPackage(ctx context.Context, packageRoot, selectedSubdir string) (Resolution, error) {
	localPath := packageRoot
	if selectedSubdir != "" {
		localPath = filepath.Join(packageRoot, filepath.FromSlash(selectedSubdir))
	}
	return ConfineResolution(ctx, Resolution{
		LocalPath:   localPath,
		PackageRoot: packageRoot,
	})
}

func cacheableModule(source, version string) bool {
	st, _ := tfmodules.DetectModuleSourceType(source)
	if st == sourceTypeRegistry {
		return isBareVersion(version)
	}
	if idx := strings.Index(source, "::"); idx != -1 {
		source = source[idx+2:]
	}
	u, err := url.Parse(source)
	if err != nil {
		return false
	}
	ref := u.Query().Get("ref")
	return ref != "" && looksLikeSHA(ref)
}

const (
	fetchMaxAttempts    = 3
	fetchRetryBaseDelay = 250 * time.Millisecond
)

// fetch retries transient git/SSH failures so cold scans stay deterministic.
func (r *GoGetterResolver) fetch(ctx context.Context, getterSrc string) (string, error) {
	contextLogger := logger.FromContext(ctx)
	var lastErr error
	for attempt := 0; attempt < fetchMaxAttempts; attempt++ {
		if attempt > 0 {
			delay := fetchRetryBaseDelay*time.Duration(1<<(attempt-1)) +
				time.Duration(rand.Int63n(int64(fetchRetryBaseDelay))) //nolint:gosec

			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return "", lastErr
			}
			contextLogger.Warn().Err(lastErr).
				Msgf("retrying transient module fetch (attempt %d/%d): %s", attempt+1, fetchMaxAttempts, getterSrc)
		}
		tmpDir, err := r.fetchWithShallowFallback(ctx, getterSrc)
		if err == nil {
			return tmpDir, nil
		}
		lastErr = err
		if !isTransientFetchError(err) {
			return "", err
		}
	}
	return "", lastErr
}

// fetchWithShallowFallback retries without depth only when the git server rejects shallow fetches.
func (r *GoGetterResolver) fetchWithShallowFallback(ctx context.Context, getterSrc string) (string, error) {
	tmpDir, err := r.fetchOnce(ctx, getterSrc)
	if err == nil {
		return tmpDir, nil
	}
	fallback := withoutDepth(getterSrc)
	if fallback == getterSrc {
		return "", err
	}
	if !isShallowUnsupportedError(err) {
		return "", err
	}
	contextLogger := logger.FromContext(ctx)
	contextLogger.Warn().
		Err(err).
		Msgf("shallow clone rejected by server; retrying as full clone: %s", getterSrc)
	return r.fetchOnce(ctx, fallback)
}

// isTransientFetchError reports connection-level fetch failures worth retrying.
func isTransientFetchError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	nonRetryable := []string{
		"no such host",
		"returned http",
		"exceeds per-module limit",
		"byte cap exceeded",
		"fetching is disabled",
		"not allowed by host allowlist",
	}
	for _, s := range nonRetryable {
		if strings.Contains(msg, s) {
			return false
		}
	}
	retryable := []string{
		"early eof",
		"session open refused",
		"session request failed",
		"connection reset",
		"connection refused",
		"broken pipe",
		"timed out",
		"timeout",
		"the remote end hung up",
		"rpc failed",
		"unexpected disconnect",
		"could not read from remote repository",
		"ssh_exchange_identification",
		"kex_exchange_identification",
	}
	for _, s := range retryable {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

func isShallowUnsupportedError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "shallow") ||
		strings.Contains(msg, "unadvertised object") ||
		strings.Contains(msg, "not our ref") ||
		strings.Contains(msg, "upload-pack: not our ref")
}

func (r *GoGetterResolver) fetchOnce(ctx context.Context, getterSrc string) (string, error) {
	r.cfg.fetchCount.Add(1)
	base := r.cfg.TmpDir
	if base == "" {
		base = os.TempDir()
	}
	tmpDir, err := os.MkdirTemp(base, "iac-module-*")
	if err != nil {
		return "", &tfmodules.UnresolvedError{Reason: "creating temp dir: " + err.Error()}
	}

	timeout := r.cfg.FetchTimeout
	if timeout <= 0 {
		timeout = DefaultFetchTimeout
	}
	fetchCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client := &getter.Client{
		Ctx:             fetchCtx,
		Src:             getterSrc,
		Dst:             tmpDir,
		Pwd:             tmpDir,
		Mode:            getter.ClientModeDir,
		DisableSymlinks: true,
		Decompressors:   r.decompressors(fetchCtx),
		Options: []getter.ClientOption{
			getter.WithGetters(r.getters(getterSrc)),
		},
	}
	if err := client.Get(); err != nil {
		_ = os.RemoveAll(tmpDir)
		var budgetErr *BudgetExceededError
		if errors.As(err, &budgetErr) {
			return "", budgetErr
		}
		return "", &tfmodules.UnresolvedError{Reason: "fetch failed: " + err.Error()}
	}
	return tmpDir, nil
}

func (r *GoGetterResolver) getters(source string) map[string]getter.Getter {
	getters := make(map[string]getter.Getter)
	if !isHTTPGetterSource(source) {
		getters["file"] = getter.Getters["file"]
	}
	httpGetter := &getter.HttpGetter{
		Netrc:              true,
		Client:             r.cfg.httpClient,
		XTerraformGetLimit: maxHTTPRedirects,
	}
	getters["http"] = httpGetter
	getters["https"] = httpGetter
	return getters
}

func (r *GoGetterResolver) decompressors(ctx context.Context) map[string]getter.Decompressor {
	limits := ResourceBudgetFromContext(ctx).Limits()
	return limitedDecompressors(limits, r.maxPackageBytes(ctx))
}

func (r *GoGetterResolver) maxPackageBytes(ctx context.Context) int64 {
	maxBytes := r.cfg.MaxModuleBytes
	if budgetMax := ResourceBudgetFromContext(ctx).Limits().MaxPackageBytes; budgetMax > 0 &&
		(maxBytes <= 0 || budgetMax < maxBytes) {
		maxBytes = budgetMax
	}
	return maxBytes
}

func validateGetterSourceTransport(source string) error {
	forced := ""
	if value, rest, ok := strings.Cut(source, "::"); ok {
		forced = strings.ToLower(value)
		source = rest
	}
	parsed, err := url.Parse(source)
	if err != nil {
		return &tfmodules.UnresolvedError{Reason: "invalid module source transport: " + err.Error()}
	}
	scheme := strings.ToLower(parsed.Scheme)
	if forced == sourceTypeGit {
		return &tfmodules.UnresolvedError{
			Reason: fmt.Sprintf(
				"network git transport %q is disabled unless it is pinned by BareGitResolver, which requires a ref=",
				scheme,
			),
		}
	}
	if forced != "" {
		scheme = forced
	}
	switch scheme {
	case httpScheme, httpsScheme, "file":
		return nil
	case "ssh", "git", "s3", "gcs", "hg":
		return &tfmodules.UnresolvedError{
			Reason: fmt.Sprintf("module transport %q is disabled because destination policy cannot be enforced", scheme),
		}
	default:
		return &tfmodules.UnresolvedError{Reason: fmt.Sprintf("module transport %q is not supported", scheme)}
	}
}

func isHTTPGetterSource(source string) bool {
	if forced, rest, ok := strings.Cut(source, "::"); ok {
		if forced != "" {
			return forced == httpScheme || forced == httpsScheme
		}
		source = rest
	}
	parsed, err := url.Parse(source)
	return err == nil && (parsed.Scheme == httpScheme || parsed.Scheme == httpsScheme)
}

func modifyGitURL(rawURL string, modify func(url.Values) bool) string {
	const gitScheme = "git::"
	if !strings.HasPrefix(rawURL, gitScheme) {
		return rawURL
	}
	u, err := url.Parse(rawURL[len(gitScheme):])
	if err != nil {
		return rawURL
	}
	q := u.Query()
	if !modify(q) {
		return rawURL
	}
	u.RawQuery = q.Encode()
	return gitScheme + u.String()
}

// withDepth adds depth=1 for shallow clones; skipped for SHA refs.
func withDepth(rawURL string) string {
	return modifyGitURL(rawURL, func(q url.Values) bool {
		if q.Get("depth") != "" || looksLikeSHA(q.Get("ref")) {
			return false
		}
		q.Set("depth", "1")
		return true
	})
}

func withoutDepth(rawURL string) string {
	return modifyGitURL(rawURL, func(q url.Values) bool {
		if q.Get("depth") == "" {
			return false
		}
		q.Del("depth")
		return true
	})
}

func (r *GoGetterResolver) checkAllowlist(source string) error {
	return checkHostAllowlist(source, r.cfg.HostAllowlist)
}

func checkHostAllowlist(source string, allowlist []string) error {
	if len(allowlist) == 0 {
		return nil
	}
	host := extractSourceHost(source)
	for _, allowed := range allowlist {
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			return nil
		}
	}
	return &tfmodules.UnresolvedError{
		Reason: fmt.Sprintf("module host %q is not in --module-host-allowlist", host),
	}
}

func extractSourceHost(source string) string {
	// Strip getter prefix (git::, …).
	if idx := strings.Index(source, "::"); idx != -1 {
		source = source[idx+2:]
	}
	// SCP-style: [user@]hostname:path — must be checked before url.Parse which misreads it.
	if at := strings.IndexByte(source, '@'); at != -1 {
		after := source[at+1:]
		if colon := strings.IndexByte(after, ':'); colon != -1 {
			if h := after[:colon]; !strings.ContainsRune(h, '/') {
				return stripPort(h)
			}
		}
	}
	if u, err := url.Parse(source); err == nil && u.Host != "" {
		return u.Hostname()
	}
	// host/path shorthand
	if slash := strings.IndexByte(source, '/'); slash > 0 {
		host := stripPort(source[:slash])
		if strings.ContainsRune(host, '.') {
			return host
		}
	}
	return defaultRegistryHost
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
