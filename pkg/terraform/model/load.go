/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

import (
	"context"
	"path/filepath"
	"slices"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcljson "github.com/hashicorp/hcl/v2/json"
)

// Scan is every root found under a directory.
type Scan struct {
	Base  string
	Roots []*Root
}

// dirInfo is what loading reads of one directory before evaluation.
type dirInfo struct {
	configs  []string
	varFiles []string
	vars     []string
	failed   []string
}

// Layout is the directories and plan files under a base, before any root is
// evaluated. Evaluating one root at a time keeps a single root's values live.
type Layout struct {
	Base  string
	fsys  vfs.FS
	dirs  map[string]*dirInfo
	Roots []string
	Plans []string
	// eval is shared across roots so a module directory is parsed once. Nil
	// until the first Root call.
	eval *tfeval.Evaluator
}

// ScanLayout finds the roots under base without evaluating them. A root is a
// directory holding configuration files that no other directory under base
// calls as a local module. Hidden directories (.git, .terraform) are skipped.
// Each file of opts.Plans is listed after the source roots. When opts.Files
// is set, only the directories of those files can be roots, and only those
// files and the modules they call are read.
func ScanLayout(ctx context.Context, base string, opts Options) (*Layout, error) {
	fsys := opts.FS
	if fsys == nil {
		fsys = vfs.DiskFS{}
	}
	abs, err := fsys.Abs(base)
	if err != nil {
		return nil, err
	}
	dirs := map[string]*dirInfo{}
	called := map[string]bool{}
	switch {
	case opts.Files != nil:
		fsys = newScannedFS(fsys, opts.Files, opts.Plans)
		if !opts.PlansOnly {
			if err := scanFiles(ctx, fsys, opts.Resolver, abs, opts.Files, dirs, called); err != nil {
				return nil, err
			}
		}
	case !opts.PlansOnly:
		if err := walkCalls(ctx, fsys, abs, dirs, called); err != nil {
			return nil, err
		}
	}
	layout := &Layout{Base: abs, fsys: fsys, dirs: dirs}
	for _, dir := range slices.Sorted(mapsKeys(dirs)) {
		if called[dir] || len(dirs[dir].configs) == 0 {
			continue
		}
		layout.Roots = append(layout.Roots, dir)
	}
	plans := slices.Clone(opts.Plans)
	slices.Sort(plans)
	for _, plan := range slices.Compact(plans) {
		path, err := fsys.Abs(plan)
		if err != nil {
			return nil, err
		}
		layout.Plans = append(layout.Plans, path)
	}
	return layout, nil
}

// Root evaluates one source directory of the layout.
func (l *Layout) Root(ctx context.Context, resolver tfeval.RemoteResolver, dir string) *Root {
	return loadRoot(ctx, l.fsys, resolver, l.Base, dir, l.dirs, l.evaluator(resolver))
}

// evaluator is the scan-wide evaluator: its parse cache is shared across
// roots, and each root releases its evaluation cache when it finishes.
func (l *Layout) evaluator(resolver tfeval.RemoteResolver) *tfeval.Evaluator {
	if l.eval == nil {
		l.eval = tfeval.NewWithFS(l.fsys)
		l.eval.SetOpaquePartialData(true)
		l.eval.SetTrackModuleInstances(true)
	}
	if resolver != nil {
		l.eval.SetRemoteResolver(resolver)
	}
	return l.eval
}

// Plan evaluates one plan file of the layout.
func (l *Layout) Plan(ctx context.Context, path string) *Root {
	return loadPlan(ctx, l.fsys, l.Base, path)
}

// Load finds the roots under base and models each of them.
func Load(ctx context.Context, base string, opts Options) (*Scan, error) {
	layout, err := ScanLayout(ctx, base, opts)
	if err != nil {
		return nil, err
	}
	scan := &Scan{Base: layout.Base, Roots: make([]*Root, 0, len(layout.Roots)+len(layout.Plans))}
	for _, dir := range layout.Roots {
		scan.Roots = append(scan.Roots, layout.Root(ctx, opts.Resolver, dir))
	}
	for _, path := range layout.Plans {
		scan.Roots = append(scan.Roots, layout.Plan(ctx, path))
	}
	return scan, nil
}

func mapsKeys(m map[string]*dirInfo) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// walkCalls fills dirs with every directory under base and marks the ones
// another of them calls as a local module.
func walkCalls(ctx context.Context, fsys vfs.FS, base string, dirs map[string]*dirInfo, called map[string]bool) error {
	if err := walk(ctx, fsys, base, dirs); err != nil {
		return err
	}
	for dir := range dirs {
		for _, child := range tfeval.CalledLocalDirs(dir, fsys) {
			if filepath.Clean(child) != dir {
				called[filepath.Clean(child)] = true
			}
		}
	}
	return nil
}

func walk(ctx context.Context, fsys vfs.FS, dir string, out map[string]*dirInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, subdirs, err := readDirInfo(fsys, dir)
	if err != nil {
		return err
	}
	if info != nil {
		out[filepath.Clean(dir)] = info
	}
	for _, sub := range subdirs {
		if err := walk(ctx, fsys, sub, out); err != nil {
			return err
		}
	}
	return nil
}

// readDirInfo reads the files of dir, and lists its subdirectories that are
// not hidden. The info is nil when dir holds no configuration or variable
// file.
func readDirInfo(fsys vfs.FS, dir string) (*dirInfo, []string, error) {
	entries, err := fsys.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	info := &dirInfo{}
	var subdirs []string
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(dir, name)
		if entry.IsDir() {
			if !strings.HasPrefix(name, ".") {
				subdirs = append(subdirs, path)
			}
			continue
		}
		switch {
		case tfpath.IsConfig(path):
			info.configs = append(info.configs, path)
			info.noteParse(fsys, path)
		case tfpath.IsPlainJSON(path):
			src, readErr := fsys.ReadFile(path)
			if readErr == nil && tfpath.LooksLikeJSONConfig(src) {
				info.configs = append(info.configs, path)
				info.noteParse(fsys, path)
			}
		case strings.HasSuffix(name, ".tfvars") || tfpath.IsTFVarsJSON(path):
			info.varFiles = append(info.varFiles, path)
		}
	}
	if len(info.configs) == 0 && len(info.varFiles) == 0 {
		return nil, subdirs, nil
	}
	return info, subdirs, nil
}

// noteParse records whether the file parses. Variable names are read from the
// evaluator when a root needs the degraded path.
func (d *dirInfo) noteParse(fsys vfs.FS, path string) {
	src, err := fsys.ReadFile(path)
	if err != nil {
		d.failed = append(d.failed, path)
		return
	}
	var body hcl.Body
	var diags hcl.Diagnostics
	if tfpath.UsesJSONSyntax(path) {
		var f *hcl.File
		f, diags = hcljson.Parse(src, path)
		if f != nil {
			body = f.Body
		}
	} else {
		var f *hcl.File
		f, diags = hclsyntax.ParseConfig(src, path, hcl.InitialPos)
		if f != nil {
			body = f.Body
		}
	}
	if diags.HasErrors() || body == nil {
		d.failed = append(d.failed, path)
	}
}

func loadRoot(
	ctx context.Context, fsys vfs.FS, resolver tfeval.RemoteResolver, base, dir string, dirs map[string]*dirInfo,
	eval *tfeval.Evaluator,
) *Root {
	root := &Root{ID: rootID(base, dir), Dir: dir}
	info := dirs[dir]
	root.VarFiles = info.varFiles
	ev := evaluate(ctx, fsys, resolver, dir, info.vars, eval)
	root.Degraded = ev.degraded
	root.Notes = ev.notes(base)
	if len(ev.skipped) > 0 || ev.err != nil {
		root.Incomplete, root.Unscoped = true, true
	}
	root.Modules = ev.modules(root, dir)
	for _, m := range root.Modules {
		if d, ok := dirs[filepath.Clean(m.Dir)]; ok && len(d.failed) > 0 {
			root.Incomplete, root.Unscoped = true, true
			for _, f := range d.failed {
				root.Notes = append(root.Notes, "file failed to parse: "+relPath(base, f))
				contextLogger := logger.FromContext(ctx)
				contextLogger.Info().Str("file", f).Msg("terraform model: file failed to parse")
			}
		}
	}
	root.Notes = slices.Compact(root.Notes)
	newBuilder(root, base).build(ev.resources)
	for _, m := range root.Modules {
		m.Scope.ReleaseEvalState()
	}
	return root
}

func rootID(base, dir string) string {
	rel, err := filepath.Rel(base, dir)
	if err != nil {
		return filepath.ToSlash(dir)
	}
	return filepath.ToSlash(rel)
}

func relPath(base, path string) string {
	if rel, err := filepath.Rel(base, path); err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(path)
}

// MayDeclareResource reports, without evaluating, whether the root at dir may
// declare a resource of one of types.
func (l *Layout) MayDeclareResource(ctx context.Context, resolver tfeval.RemoteResolver, dir string, types func(string) bool) bool {
	return l.evaluator(resolver).MayDeclareResource(ctx, dir, types)
}

// CalledModuleDirectories returns the module directories any root may reach
// without instantiating resources.
func (l *Layout) CalledModuleDirectories(ctx context.Context, resolver tfeval.RemoteResolver) map[string]bool {
	called := make(map[string]bool)
	eval := l.evaluator(resolver)
	for _, dir := range l.Roots {
		if ctx.Err() != nil {
			break
		}
		for _, d := range eval.CalledModuleTree(ctx, dir) {
			called[filepath.Clean(d)] = true
		}
	}
	return called
}
