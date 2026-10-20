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

// renderMu serializes krusty builds process-wide: krusty.Run installs an
// OpenAPI schema into a package variable of kyaml, whose readers take no lock
// of their own, so a per-Renderer lock would let one renderer's reset wipe
// the schema another renderer's build is reading.
var renderMu sync.Mutex

// Renderer renders kustomization roots of one scan. It is scan-scoped state:
// a byte cache shared by all renders and a cumulative size budget. Renders
// themselves are serialized, process-wide, because krusty.Run mutates
// process-global OpenAPI state and is not safe for concurrent use.
type Renderer struct {
	fsys            vfs.FS
	confinementRoot string
	maxFileBytes    int64
	budget          atomic.Int64
	cache           *byteCache
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
	renderMu.Lock()
	defer renderMu.Unlock()
	// Any kustomization the build touches can install a custom schema, not
	// just the render root, and SetSchema never clears a previous one. Reset
	// when the version changed, deferred and under renderMu, so the error and
	// panic paths are covered and the reset cannot race a concurrent render.
	// ResetOpenAPI also drops the parsed builtin schema, which the next
	// render rebuilds, so it is only paid for renders that changed the schema.
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

// relative returns p relative to the confinement root, "." for the root
// itself, so no machine path reaches finding metadata. Separators follow the
// filesystem, as the Helm resolver does: pushed files are reported with "/"
// on every OS, disk files keep the OS separator. p must be relative to the
// confinement root or a rooted path already resolved through realPath, which
// is what every caller holds.
func (c *constrainedFS) relative(p string) string {
	rel, err := filepath.Rel(c.confinementRoot, absUnderRoot(c.confinementRoot, p))
	if err != nil {
		// Unreachable for a confined path: both sides are absolute and share a
		// volume. Report no path rather than an absolute one; mapResources
		// drops entries that have no file name to report against.
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
// recognize the top-level file.
func findKustomizationFile(cfs *constrainedFS, renderRoot string) (string, error) {
	for _, name := range []string{"kustomization.yaml", "kustomization.yml", "Kustomization"} {
		path := filepath.Join(renderRoot, name)
		if info, found, err := cfs.statExists(path); err == nil && !info.IsDir() {
			return found, nil
		}
	}
	return "", failf(ReasonMissingFile, "no kustomization file in render root")
}
