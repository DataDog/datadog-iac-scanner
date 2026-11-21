/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package eval

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/pulumi/capture"
)

// goLauncher runs a Go program: the binary named by the runtime option
// "binary" when it exists, otherwise a binary built from the project with no
// network access and the prepared module cache (D19). go.mod and go.work are
// looked for between the program and the scan root, never above it.
type goLauncher struct {
	binary string
}

// failure is why a project cannot be evaluated at all.
type failure struct {
	reason  capture.Reason
	message string
}

func newGoLauncher(ctx context.Context, p *Project, opts *Options, workDir string, env childEnv) (*goLauncher, *failure) {
	if bin := p.option("binary"); bin != "" {
		if !filepath.IsAbs(bin) {
			bin = filepath.Join(p.Dir, bin)
		}
		if isFile(bin) {
			return &goLauncher{binary: bin}, nil
		}
	}
	goTool := opts.Go
	if goTool == "" {
		found, err := lookPath("go", env["PATH"])
		if err != nil {
			return nil, &failure{capture.ReasonRuntimeMissing, "go toolchain not found on PATH"}
		}
		goTool = found
	} else if !isFile(goTool) {
		return nil, &failure{capture.ReasonRuntimeMissing, "go toolchain " + goTool + " not found"}
	}

	mainDir := p.Dir
	if p.Main != "" {
		mainDir = filepath.Join(p.Dir, p.Main)
	}
	modRoot := findUp(mainDir, opts.Root, "go.mod")
	if modRoot == "" {
		return nil, &failure{capture.ReasonBuildFailed, "no go.mod between " + mainDir + " and the scan root"}
	}
	gopath := filepath.Join(workDir, "gopath")
	if err := os.MkdirAll(gopath, dirPerm); err != nil {
		return nil, &failure{capture.ReasonBuildFailed, err.Error()}
	}
	settings := goSettings{modCache: opts.GoModCache, cache: opts.GoCache, path: gopath}
	// A workspace (go.work) is used as `go build` would find it, but only
	// inside the scan root (D19): some projects build only in their workspace.
	if ws := findUp(mainDir, opts.Root, "go.work"); ws != "" {
		settings.work = resolveLinks(filepath.Join(ws, "go.work"))
		settings.vendored = isFile(filepath.Join(ws, "vendor", "modules.txt"))
	} else {
		settings.vendored = isFile(filepath.Join(modRoot, "vendor", "modules.txt"))
	}
	// go matches the current directory against the workspace's modules after
	// resolving symbolic links on one side only, so build from the real path
	// (the scan root can sit under a link, such as macOS's /var).
	mainDir = resolveLinks(mainDir)
	binary := filepath.Join(workDir, "pulumi-program")
	build := run(ctx, &command{
		argv:    []string{goTool, "build", "-buildvcs=false", "-o", binary, "."},
		dir:     mainDir,
		env:     env.withGo(settings),
		timeout: opts.BuildTimeout,
	})
	switch {
	case build.timedOut:
		return nil, &failure{capture.ReasonTimeout, "go build did not finish in " + opts.BuildTimeout.String()}
	case build.err != nil:
		return nil, &failure{classifyBuild(build.output), excerpt(build.output)}
	}
	return &goLauncher{binary: binary}, nil
}

// findUp returns the closest directory at or above dir that holds the file
// name, looking no higher than root. It returns "" when dir is not under root.
func findUp(dir, root, name string) string {
	if !under(root, dir) {
		return ""
	}
	for d := dir; ; d = filepath.Dir(d) {
		if isFile(filepath.Join(d, name)) {
			return d
		}
		if d == root || filepath.Dir(d) == d {
			return ""
		}
	}
}

// resolveLinks resolves the symbolic links in path, or returns it as is.
func resolveLinks(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
}

// under reports whether path is root or inside it.
func under(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && !filepath.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func (l *goLauncher) command(p *Project, _ /* stack */, _ /* addr */ string, env childEnv) *command {
	return &command{argv: []string{l.binary}, dir: p.programDir(), env: env}
}
