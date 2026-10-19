/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2025 Datadog, Inc.
 */
package kustomize

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/api/resmap"
	"sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/openapi"
)

// Result carries the outcome of one render root.
type Result struct {
	// Root is the render root relative to the confinement root, forward slashes.
	Root string
	// Entries are the rendered resources attributed to their source documents.
	Entries []model.ResolvedHelm
	// ReadFiles lists the files the render served, sorted absolute paths.
	ReadFiles []string
	// MappingFailures counts rendered resources with no exact source document.
	MappingFailures int
}

// Renderer renders kustomization roots of one scan. It is scan-scoped state:
// a byte cache shared by all renders and a cumulative size budget. Renders
// themselves are serialized because krusty.Run mutates process-global OpenAPI
// state and is not safe for concurrent use.
type Renderer struct {
	fsys            vfs.FS
	confinementRoot string
	maxFileBytes    int64
	budget          atomic.Int64
	cache           *byteCache
	runMu           sync.Mutex
}

// NewRenderer returns a renderer confined to confinementRoot. maxFileBytes
// caps one file; zero selects the default.
func NewRenderer(fsys vfs.FS, confinementRoot string, maxFileBytes int64) *Renderer {
	if maxFileBytes <= 0 {
		maxFileBytes = DefaultMaxFileBytes
	}
	r := &Renderer{
		fsys:            fsys,
		confinementRoot: confinementRoot,
		maxFileBytes:    maxFileBytes,
		cache:           &byteCache{files: make(map[string][]byte)},
	}
	r.budget.Store(MaxTotalBytes)
	return r
}

// Render renders the kustomization at root (relative to the confinement root)
// and maps every rendered resource to its source document. On any skip or
// failure the caller falls back to scanning the raw files.
func (r *Renderer) Render(ctx context.Context, root string) (*Result, error) {
	log := logger.FromContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cfs, err := newConstrainedFS(r.fsys, r.confinementRoot, root, r.maxFileBytes, &r.budget, r.cache)
	if err != nil {
		return nil, err
	}
	top, err := findKustomizationFile(cfs, cfs.renderRoot)
	if err != nil {
		return nil, err
	}
	cfs.topKustomFile = top

	topKust, err := cfs.loadKustomization(top)
	if err != nil {
		return nil, err
	}

	log.Debug().Msgf("kustomize rendering root %s", root)
	resMap, err := r.run(cfs)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	entries, failures := mapResources(r.fsys, cfs, resMap, topKust.NamePrefix, topKust.NameSuffix)
	return &Result{
		// The resolved render root is the single source of truth, so Root and
		// every entry's RenderRoot agree whatever form the caller passed.
		Root:            cfs.relative(cfs.renderRoot),
		Entries:         entries,
		ReadFiles:       cfs.read.sorted(),
		MappingFailures: failures,
	}, nil
}

// run performs the krusty build under the serialization lock, converting a
// panic into a render error so hostile input cannot take down the scan.
func (r *Renderer) run(cfs *constrainedFS) (resMap resmap.ResMap, err error) {
	defer func() {
		if p := recover(); p != nil {
			resMap = nil
			err = failf(ReasonRenderError, "kustomize render panicked")
		}
	}()
	r.runMu.Lock()
	defer r.runMu.Unlock()
	// A custom schema must not leak into later renders. Any kustomization the
	// build touches can install one, not just the render root's own: a base or
	// component calls SetSchema too, and SetSchema never clears a previous
	// custom schema, so the next render would silently patch under it. Compare
	// the schema version instead of the root's openapi field to catch those,
	// and reset here, under runMu and deferred, so the success, error, and
	// panic paths are all covered and the reset cannot race a concurrent
	// render that reads the same process-global state. ResetOpenAPI also drops
	// the parsed builtin schema, which the next render rebuilds, so it is
	// still only paid for renders that actually changed the schema.
	schemaBefore := openapi.GetSchemaVersion()
	defer func() {
		if openapi.GetSchemaVersion() != schemaBefore {
			openapi.ResetOpenAPI()
		}
	}()
	opts := krusty.MakeDefaultOptions()
	opts.LoadRestrictions = types.LoadRestrictionsNone
	resMap, err = krusty.MakeKustomizer(opts).Run(cfs, cfs.renderRoot)
	if err != nil {
		return nil, failf(ReasonRenderError, "kustomize render failed")
	}
	return resMap, nil
}

// relative returns p relative to the confinement root. The render root itself
// is ".", never the absolute path it resolves to, so no machine path reaches
// finding metadata. Separators follow the filesystem, as the Helm resolver
// does: pushed files are reported with "/" on every OS, disk files keep the
// OS separator. p must be relative to the confinement root or an absolute
// path already resolved through realPath, which is what every caller holds;
// an unresolved absolute path would not share the resolved root's prefix.
func (c *constrainedFS) relative(p string) string {
	abs := p
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(c.confinementRoot, abs)
	}
	rel, err := filepath.Rel(c.confinementRoot, filepath.Clean(abs))
	if err != nil {
		// Unreachable for a confined path: both are absolute and, having
		// passed the confinement check, share a volume. Report no path rather
		// than fall back to an absolute one; mapResources drops entries that
		// have no file name to report against.
		return ""
	}
	if c.slashPaths {
		return filepath.ToSlash(rel)
	}
	return rel
}

// findKustomizationFile returns the render root's kustomization file, probing
// the three names Kustomize itself recognizes, in its own probe order. It
// returns the resolved path, which is what ReadFile compares against to
// recognize the top-level file: a symlinked kustomization.yaml would otherwise
// never be annotated, and every resource would lose its source attribution.
func findKustomizationFile(cfs *constrainedFS, renderRoot string) (string, error) {
	for _, name := range []string{"kustomization.yaml", "kustomization.yml", "Kustomization"} {
		path := filepath.Join(renderRoot, name)
		if info, found, err := cfs.statExists(path); err == nil && !info.IsDir() {
			return found, nil
		}
	}
	return "", failf(ReasonMissingFile, "no kustomization file in render root")
}
