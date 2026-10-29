package runner

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/provider"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/resolver/kustomize"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

// renderKustomizeRoots renders the top-level kustomizations of a disk scan,
// stores their documents for the Kubernetes parsers and returns files without
// those the successful renders consumed. Anything not rendered is scanned raw.
//
// Roots render and store one after the other; Kustomize serializes
// Run anyway, and storing per root keeps one root's documents in memory.
func renderKustomizeRoots(ctx context.Context, settings *provider.KustomizeSettings, chartRoots []string,
	services []*Service, files []provider.InventoryFile, scanID string,
	openAPIResolveReferences bool, maxResolverDepth int) []provider.InventoryFile {
	if settings == nil || len(settings.Roots) == 0 {
		return files
	}
	k8s := kubernetesServices(services)
	if len(k8s) == 0 {
		return files
	}
	contextLogger := logger.FromContext(ctx)
	start := time.Now()

	listed, dirs, charts, repo := kustomizeInputPaths(settings, chartRoots, files)
	renderer := kustomize.NewRenderer(vfs.Default(), repo, settings.MaxFileBytes)
	defer renderer.Release()
	// The planner reads through the renderer's confined, regular-file-only,
	// bounded reader: no repository read bypasses the render's bounds.
	plan := kustomize.Plan(dirs, charts, renderer.BoundedRead())

	consumed := map[string]struct{}{}
	// unrendered holds the directories and files a skipped root reaches.
	unrendered := map[string]struct{}{}
	reasons := map[string]int{}
	stats := kustomizeStats{}
	planDone := time.Now()
	for _, root := range plan {
		rel := renderRootPath(repo, root.Dir)
		renderStart := time.Now()
		res, resFiles, reads, skip := renderPlannedRoot(ctx, renderer, root, rel, listed)
		stats.renderNs += time.Since(renderStart)
		if skip != "" {
			markUnrendered(unrendered, root)
			reasons[skip]++
			contextLogger.Debug().Msgf("Kustomize root '%s' not rendered: %s", rel, skip)
			continue
		}
		stats.rendered++
		stats.mappingFailures += res.MappingFailures
		stats.runNs += res.RunNs
		stats.mapNs += res.MapNs
		if f := k8s[0].RenderedFileFilter; f != nil {
			resFiles = withoutExcludedFiles(ctx, f, rel, resFiles)
		}
		stats.docs += len(resFiles.File)
		storeStart := time.Now()
		for _, s := range k8s {
			s.storeResolvedFiles(ctx, resFiles, model.KindKUSTOMIZE, scanID, openAPIResolveReferences, maxResolverDepth)
		}
		stats.storeNs += time.Since(storeStart)
		for _, p := range reads {
			if kustomize.IsKustomizationFile(filepath.Base(p)) || isKubernetesPlatform(sharedFilePlatform(services, listed[p])) {
				consumed[p] = struct{}{}
			}
		}
	}
	for _, s := range k8s {
		s.kustomizeSources = nil
	}
	logKustomizeSummary(ctx, stats.rendered, stats.docs, stats.mappingFailures,
		reasons, time.Since(start), stats.runNs, stats.mapNs, stats.storeNs, planDone.Sub(start))

	return withoutConsumedFiles(files, renderedOnly(consumed, unrendered))
}

// renderedOnly drops from consumed the files a skipped root also reaches;
// when a skipped root's reach is unknown, nothing is consumed.
func renderedOnly(consumed, unrendered map[string]struct{}) map[string]struct{} {
	if _, unknown := unrendered[""]; unknown {
		return nil
	}
	for p := range consumed {
		_, inDir := unrendered[filepath.Dir(p)]
		_, listed := unrendered[p]
		if inDir || listed {
			delete(consumed, p)
		}
	}
	return consumed
}

// markUnrendered records the kustomization directories a skipped root
// reaches and the files they reference: they stay scanned as written even
// when another root rendered them. A root the planner refused has an
// incomplete reach: it is recorded as "", which keeps every file scanned as
// written. Paths are symlink-resolved, like the render's reads they are
// compared with.
func markUnrendered(unrendered map[string]struct{}, root kustomize.PlannedRoot) {
	if root.Skip == kustomize.ReasonPlanSkip {
		unrendered[""] = struct{}{}
		return
	}
	unrendered[absPath(root.Dir)] = struct{}{}
	for d := range root.Closure {
		unrendered[absPath(d)] = struct{}{}
	}
	for _, f := range root.Files {
		unrendered[absPath(f)] = struct{}{}
	}
}

// kustomizeStats aggregates the per-root counters of a render phase.
type kustomizeStats struct {
	rendered, docs, mappingFailures int
	renderNs, storeNs, runNs, mapNs time.Duration
}

// kustomizeInputPaths maps every scanned file and root to its absolute path.
func kustomizeInputPaths(settings *provider.KustomizeSettings, chartRoots []string,
	files []provider.InventoryFile) (listed map[string]string, dirs, charts []string, repo string) {
	listed = make(map[string]string, len(files))
	for _, f := range files {
		listed[absPath(f.Path)] = f.Path
	}
	for _, d := range settings.Roots {
		dirs = append(dirs, absPath(d))
	}
	for _, c := range chartRoots {
		charts = append(charts, absPath(c))
	}
	return listed, dirs, charts, absPath(settings.RepoPath)
}

// renderPlannedRoot renders one planned root and returns its stored files plus
// the files the render read; skip is the reason the root was not rendered.
func renderPlannedRoot(ctx context.Context, renderer *kustomize.Renderer, root kustomize.PlannedRoot, rel string,
	listed map[string]string) (res kustomize.Result, files model.ResolvedFiles, reads []string, skip string) {
	if root.Skip != "" {
		return kustomize.Result{}, model.ResolvedFiles{}, nil, root.Skip
	}
	r, err := renderer.Render(ctx, root.Dir, nil)
	if err != nil {
		var re *kustomize.RenderError
		reason := kustomize.ReasonRenderError
		if errors.As(err, &re) {
			reason = re.Reason
		}
		return kustomize.Result{}, model.ResolvedFiles{}, nil, reason
	}
	res = *r
	files = rootFileList(&res, rel, listed)
	return res, files, r.Reads, ""
}

// rootFileList turns a rendered result into the resolved files stored for the
// Kubernetes services, rewriting paths to their listed names.
func rootFileList(res *kustomize.Result, rel string, listed map[string]string) model.ResolvedFiles {
	resFiles := model.ResolvedFiles{File: make([]model.ResolvedHelm, 0, len(res.Documents))}
	for i := range res.Documents {
		d := &res.Documents[i]
		d.Kustomize.RenderRoot = rel
		if p, ok := listed[d.FileName]; ok {
			d.FileName = p
		}
		resFiles.File = append(resFiles.File, *d)
	}
	return resFiles
}

// withoutConsumedFiles drops the inventory files a successful render consumed.
func withoutConsumedFiles(files []provider.InventoryFile, consumed map[string]struct{}) []provider.InventoryFile {
	if len(consumed) == 0 {
		return files
	}
	kept := files[:0]
	for _, f := range files {
		if _, ok := consumed[absPath(f.Path)]; !ok {
			kept = append(kept, f)
		}
	}
	return kept
}

func kubernetesServices(services []*Service) []*Service {
	var out []*Service
	for _, s := range services {
		if s.Parser.Parsers.GetKind() == model.KindYAML && containsPlatformFold(s.Parser.Platform, "kubernetes") {
			out = append(out, s)
		}
	}
	return out
}

func isKubernetesPlatform(platform string) bool {
	return strings.EqualFold(platform, "kubernetes") || strings.EqualFold(platform, "knative")
}

func absPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	return filepath.Clean(p)
}

// renderRootPath is dir relative to repo, slash-separated, "." for repo.
func renderRootPath(repo, dir string) string {
	rel, err := filepath.Rel(repo, dir)
	if err != nil {
		return filepath.ToSlash(dir)
	}
	return filepath.ToSlash(rel)
}

func logKustomizeSummary(ctx context.Context, rendered, docs, mappingFailures int,
	reasons map[string]int, took, runNs, mapNs, storeNs, planNs time.Duration) {
	contextLogger := logger.FromContext(ctx)
	keys := make([]string, 0, len(reasons))
	for k := range reasons {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ev := contextLogger.Info().Int("roots_rendered", rendered).Int("documents", docs).
		Int("mapping_failures", mappingFailures).
		Int64("render_ms", took.Milliseconds()).
		Int64("plan_ms", planNs.Milliseconds()).
		Int64("krusty_ms", runNs.Milliseconds()).
		Int64("mapping_ms", mapNs.Milliseconds()).
		Int64("store_ms", storeNs.Milliseconds())
	for _, k := range keys {
		ev = ev.Int("skipped_"+k, reasons[k])
	}
	ev.Msg("Kustomize roots rendered")
	if n := reasons[kustomize.ReasonRenderError] + reasons[kustomize.ReasonTimeout]; n > 0 {
		contextLogger.Warn().Msgf("%d Kustomize roots could not be rendered; their files are scanned as written", n)
	}
}
