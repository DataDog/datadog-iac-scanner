/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package eval

import (
	_ "embed" // embeds the official Python launcher
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

// pythonExec is the official launcher Pulumi uses to run Python programs,
// copied unchanged from github.com/pulumi/pulumi/sdk/v3@v3.272.0
// (python/cmd/pulumi-language-python-exec; Apache-2.0, Copyright 2016
// Pulumi Corporation).
//
//go:embed pulumi-language-python-exec
var pythonExec []byte

const pythonExecName = "pulumi-language-python-exec"

// pythonLauncher runs a Python program with the interpreter of its virtual
// environment. It never installs anything.
type pythonLauncher struct {
	python string // interpreter
	venv   string // virtual environment, "" when the interpreter is not in one
	script string // path of the launcher script
}

var errNoPython = errors.New("no Python interpreter found")

// newPythonLauncher picks the interpreter: the one given by the operator, then
// the project's virtual environment (runtime option virtualenv, or .venv with
// the uv toolchain), then python3 or python on PATH.
func newPythonLauncher(p *Project, explicit, workDir string, env childEnv) (*pythonLauncher, string, error) {
	l := &pythonLauncher{script: filepath.Join(workDir, pythonExecName)}
	switch {
	case explicit != "":
		if !isFile(explicit) {
			return nil, "python interpreter " + explicit + " not found", errNoPython
		}
		l.python, l.venv = explicit, venvOf(explicit)
	case projectVenv(p) != "":
		l.venv = projectVenv(p)
		l.python = venvPython(l.venv)
	default:
		for _, name := range []string{"python3", "python"} {
			if path, err := lookPath(name, env["PATH"]); err == nil {
				l.python = path
				break
			}
		}
		if l.python == "" {
			return nil, "python3 not found on PATH", errNoPython
		}
	}
	if err := os.WriteFile(l.script, pythonExec, filePerm); err != nil {
		return nil, "", err
	}
	return l, "", nil
}

// projectVenv returns the project's virtual environment if it exists.
func projectVenv(p *Project) string {
	dir := p.option("virtualenv")
	if dir == "" && p.option("toolchain") == "uv" {
		dir = ".venv"
	}
	if dir == "" {
		return ""
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(p.Dir, dir)
	}
	if venvPython(dir) == "" {
		return ""
	}
	return dir
}

func venvPython(venv string) string {
	for _, name := range []string{"python3", "python"} {
		if p := filepath.Join(venv, "bin", name); isFile(p) {
			return p
		}
	}
	return ""
}

// venvOf returns the virtual environment an interpreter belongs to, if any.
func venvOf(python string) string {
	dir := filepath.Dir(filepath.Dir(python))
	if isFile(filepath.Join(dir, "pyvenv.cfg")) {
		return dir
	}
	return ""
}

func (l *pythonLauncher) command(p *Project, stack, addr string, env childEnv) *command {
	program := p.Dir
	if p.Main != "" {
		program = filepath.Join(p.Dir, p.Main)
	}
	return &command{
		argv: []string{
			l.python, l.script,
			"--project", p.Name,
			"--stack", stack,
			"--parallel", strconv.Itoa(parallelism),
			"--dry_run", "true",
			"--pwd", p.programDir(),
			"--monitor", addr,
			"--engine", addr,
			"--organization", "organization",
			"--root_directory", p.Dir,
			program,
		},
		dir: p.programDir(),
		env: env.withPython(l.venv),
	}
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// lookPath finds an executable on the child's PATH (not the scanner's).
func lookPath(name, path string) (string, error) {
	for _, dir := range filepath.SplitList(path) {
		if dir == "" {
			continue
		}
		p := filepath.Join(dir, name)
		if info, err := os.Stat(p); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", exec.ErrNotFound
}
