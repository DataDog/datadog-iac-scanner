package kustomize

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/api/resmap"
	"sigs.k8s.io/kustomize/api/types"
)

const (
	// rootTimeout bounds one render. Run cannot be canceled: on expiry its
	// result is abandoned and the renderer stops rendering.
	rootTimeout = 30 * time.Second
	// PhaseTimeout bounds all the renders of a scan.
	PhaseTimeout = 60 * time.Second
)

// runLock serializes renders: krusty.Run resets process-wide OpenAPI state.
var runLock = &renderLock{changed: make(chan struct{})}

// renderLock is held by one render at a time. A render abandoned at its
// deadline keeps it until its run returns; the renders waiting for it, or
// arriving meanwhile, fail fast instead.
type renderLock struct {
	mu    sync.Mutex
	owner *lockOwner
	// changed is closed, and replaced, when the owner releases the lock or is
	// abandoned.
	changed chan struct{}
}

type lockOwner struct{ abandoned bool }

// acquire takes the lock, waiting for a live owner until ctx ends or
// deadline passes; an abandoned owner fails it at once. Both are checked
// before every grant, so a release does not win over an ended wait.
func (l *renderLock) acquire(ctx context.Context, deadline time.Time) *lockOwner {
	wait := time.NewTimer(time.Until(deadline))
	defer wait.Stop()
	for {
		if ctx.Err() != nil || time.Now().After(deadline) {
			return nil
		}
		l.mu.Lock()
		if l.owner == nil {
			l.owner = &lockOwner{}
			l.mu.Unlock()
			return l.owner
		}
		abandoned, changed := l.owner.abandoned, l.changed
		l.mu.Unlock()
		if abandoned {
			return nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return nil
		case <-wait.C:
			return nil
		}
	}
}

// release frees the lock o holds.
func (l *renderLock) release(o *lockOwner) { l.change(o, func() { l.owner = nil }) }

// abandon marks o abandoned while it still holds the lock; once it released
// it, abandoning changes nothing, so a late abandonment never marks the next
// owner.
func (l *renderLock) abandon(o *lockOwner) { l.change(o, func() { o.abandoned = true }) }

func (l *renderLock) change(o *lockOwner, f func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.owner != o {
		return
	}
	f()
	close(l.changed)
	l.changed = make(chan struct{})
}

// RenderError tells why a root did not render. It carries only a category:
// Kustomize error text may echo secret input and is dropped.
type RenderError struct{ Reason string }

func (e *RenderError) Error() string { return "kustomize render failed: " + e.Reason }

// Result is one rendered root.
type Result struct {
	Root string
	// Documents are the rendered resources, attributed to their source files.
	Documents []model.ResolvedHelm
	// Reads are the files the render consumed, sorted.
	Reads []string
	// MappingFailures counts documents whose source document was not found.
	MappingFailures int
	// RunNs is the time krusty spent building the ResMap; MapNs the time
	// mapping and attribution took afterwards.
	RunNs, MapNs time.Duration
	// graphSteps counts the steps the load graph walks took.
	graphSteps int
}

// Renderer renders the kustomizations of one scan. Its methods are safe for
// concurrent use; renders run one at a time.
type Renderer struct {
	fsys     vfs.FS
	confine  string
	cache    *sourceCache
	mu       sync.Mutex
	dead     bool
	deadline time.Time
	docs     map[string][]sourceDoc
	timeout  time.Duration
}

// NewRenderer returns a renderer reading through fsys, never outside confine.
// maxFileBytes is the size above which a file is refused unread.
func NewRenderer(fsys vfs.FS, confine string, maxFileBytes int64) *Renderer {
	if fsys == nil {
		fsys = vfs.Default()
	}
	if abs, err := fsys.Abs(confine); err == nil {
		confine = abs
	}
	if vfs.IsDisk(fsys) {
		if resolved, err := filepath.EvalSymlinks(confine); err == nil {
			confine = resolved
		}
	}
	return &Renderer{
		fsys:    fsys,
		confine: filepath.Clean(confine),
		cache: &sourceCache{
			files:    map[string][]byte{},
			kusts:    map[string]*types.Kustomization{},
			maxFile:  maxFileBytes,
			resolved: map[string]string{},
		},
		deadline: time.Now().Add(PhaseTimeout),
		docs:     map[string][]sourceDoc{},
		timeout:  rootTimeout,
	}
}

// BoundedRead returns a read function confined to the renderer root: paths
// outside it (symlinks resolved) are refused, only regular files are served,
// and the per-file and cumulative size budgets apply. The planner and the
// renderer's root preparation share it so no repository read bypasses the
// bounds and nothing can block before the render watchdog.
func (r *Renderer) BoundedRead() func(string) ([]byte, error) {
	a := &adapter{fsys: r.fsys, root: r.confine, cache: r.cache, reads: map[string]struct{}{}}
	return func(p string) ([]byte, error) {
		abs, ok := a.resolve(p)
		if !ok {
			return nil, fs.ErrNotExist
		}
		info, err := r.fsys.Stat(abs)
		if err != nil || !info.Mode().IsRegular() {
			return nil, fs.ErrNotExist
		}
		return a.load(abs, IsKustomizationFile(filepath.Base(p)))
	}
}

// Source returns the original bytes of a file a render consumed.
func (r *Renderer) Source(path string) ([]byte, bool) {
	r.cache.mu.Lock()
	defer r.cache.mu.Unlock()
	b, ok := r.cache.files[path]
	return b, ok
}

// Kustomization returns the decoded kustomization file at path, if served.
func (r *Renderer) Kustomization(path string) (*types.Kustomization, bool) {
	r.cache.mu.Lock()
	defer r.cache.mu.Unlock()
	k, ok := r.cache.kusts[path]
	return k, ok && k != nil
}

// Release drops the cached source bytes.
func (r *Renderer) Release() {
	r.cache.mu.Lock()
	r.cache.files = map[string][]byte{}
	r.cache.mu.Unlock()
	r.mu.Lock()
	r.docs = map[string][]sourceDoc{}
	r.mu.Unlock()
}

type runOutcome struct {
	m   resmap.ResMap
	a   *adapter
	err error
	// prepErr fails the root before Kustomize runs; root and kustFile are the
	// confined root and its kustomization file.
	prepErr        error
	root, kustFile string
	runNs          time.Duration
}

// prepareAndRun resolves and prepares root, then runs Kustomize on it.
func (r *Renderer) prepareAndRun(ctx context.Context, a *adapter, root string, deadline time.Time) runOutcome {
	abs, ok := resolveRoot(a, root)
	if !ok {
		return runOutcome{prepErr: &RenderError{Reason: ReasonValidation}}
	}
	kustFile, err := r.prepareRoot(a, abs, deadline)
	if err != nil {
		return runOutcome{prepErr: err}
	}
	if ctx.Err() != nil || time.Now().After(deadline) {
		return runOutcome{prepErr: &RenderError{Reason: ReasonTimeout}}
	}
	start := time.Now()
	out := run(a, abs)
	out.root, out.kustFile, out.runNs = abs, kustFile, time.Since(start)
	return out
}

// Render renders the kustomization directory root. closure carries the plan's
// verified per-directory affixes; nil falls back to deriving them from the
// render graph. One remaining-budget deadline covers preparation, execution
// and mapping: a root started near the phase deadline gets only what is left
// of it, and scan cancellation aborts the render.
func (r *Renderer) Render(ctx context.Context, root string, closure map[string]Affixes) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, &RenderError{Reason: ReasonTimeout}
	}
	r.mu.Lock()
	dead := r.dead || time.Now().After(r.deadline)
	r.mu.Unlock()
	if dead {
		return nil, &RenderError{Reason: ReasonTimeout}
	}
	r.mu.Lock()
	phase := r.deadline
	r.mu.Unlock()
	owner := runLock.acquire(ctx, phase)
	if owner == nil {
		return nil, &RenderError{Reason: ReasonTimeout}
	}
	// One absolute deadline covers preparation, execution and mapping, from
	// when the render holds the lock: a root started near the phase deadline
	// gets only what is left of it.
	r.mu.Lock()
	budget := time.Until(r.deadline)
	r.mu.Unlock()
	if budget > r.timeout {
		budget = r.timeout
	}
	deadline := time.Now().Add(budget)
	a := &adapter{fsys: r.fsys, root: r.confine, cache: r.cache, reads: map[string]struct{}{}}
	done := make(chan runOutcome, 1)
	go func() {
		out := r.prepareAndRun(ctx, a, root, deadline)
		runLock.release(owner)
		done <- out
	}()
	// The absolute root deadline bounds preparation and execution alike.
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	var out runOutcome
	select {
	case out = <-done:
	case <-timer.C:
		runLock.abandon(owner)
		r.kill()
		return nil, &RenderError{Reason: ReasonTimeout}
	case <-ctx.Done():
		runLock.abandon(owner)
		r.kill()
		return nil, &RenderError{Reason: ReasonTimeout}
	}
	if out.prepErr != nil {
		return nil, out.prepErr
	}
	abs, kustFile := out.root, out.kustFile
	if out.err != nil {
		reason := a.reason
		if reason == "" {
			reason = ReasonRenderError
		}
		return nil, &RenderError{Reason: reason}
	}
	res := &Result{Root: abs, Reads: sortedKeys(a.reads), RunNs: out.runNs}
	mapStart := time.Now()
	if err := r.mapResources(ctx, res, out.m, kustFile, closure, deadline); err != nil {
		// Abandon the result so its files fall back to the raw scan; past the
		// phase deadline or once the scan is canceled, stop rendering.
		var re *RenderError
		if errors.As(err, &re) && re.Reason == ReasonTimeout {
			r.kill()
		}
		return nil, err
	}
	res.MapNs = time.Since(mapStart)
	return res, nil
}

// resolveRoot confines root and checks Kustomize reads it as a directory.
// Kustomize parses the root as a git URL before it consults the adapter: a
// relative root (MemFS keeps paths as pushed) must be plain and local.
func resolveRoot(a *adapter, root string) (string, bool) {
	abs, ok := a.resolve(root)
	local := filepath.IsAbs(abs) || strings.HasPrefix(filepath.ToSlash(abs), "/") || isPlainLocalPath(abs)
	return abs, ok && local
}

func (r *Renderer) kill() {
	r.mu.Lock()
	r.dead = true
	r.mu.Unlock()
}

// prepareRoot loads and validates the root kustomization and builds the copy
// served in its place, with origin annotations enabled. The probe goes through
// the confined resolve: a symlinked root kustomization pointing outside is
// never stat-ed, let alone read.
func (r *Renderer) prepareRoot(a *adapter, root string, deadline time.Time) (string, error) {
	if time.Now().After(deadline) {
		return "", &RenderError{Reason: ReasonTimeout}
	}
	var kustFile string
	for _, n := range KustomizationFileNames {
		abs, _, ok := a.stat(filepath.Join(root, n))
		if !ok {
			continue
		}
		if kustFile != "" {
			return "", &RenderError{Reason: ReasonRenderError}
		}
		kustFile = abs
	}
	if kustFile == "" {
		return "", &RenderError{Reason: ReasonMissingFile}
	}
	content, err := a.load(kustFile, true)
	if err != nil {
		reason := a.reason
		if reason == "" {
			reason = ReasonMissingFile
		}
		return "", &RenderError{Reason: reason}
	}
	cp := withOriginAnnotations(content)
	if cp == nil {
		return "", &RenderError{Reason: ReasonValidation}
	}
	a.rootKust, a.rootCopy = kustFile, cp
	return kustFile, nil
}

func run(a *adapter, root string) (out runOutcome) {
	out.a = a
	// Kustomize logs var values through the standard logger (refvar); they may
	// be secrets. Its direct stderr writes are constant deprecation notices.
	defer logger.SilenceStdLog()()
	defer func() {
		if p := recover(); p != nil {
			out.m, out.err = nil, errors.New("kustomize panicked")
		}
	}()
	opts := krusty.MakeDefaultOptions()
	opts.LoadRestrictions = types.LoadRestrictionsNone
	opts.PluginConfig = types.DisabledPluginConfig()
	out.m, out.err = krusty.MakeKustomizer(opts).Run(a, root)
	return out
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
