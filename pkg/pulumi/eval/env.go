/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package eval

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

// defaultPath is used when the scanner itself has no PATH.
const defaultPath = "/usr/local/bin:/usr/bin:/bin"

// parallelism is the value of PULUMI_PARALLEL given to programs.
const parallelism = 8

// passThroughVars are passed through when set: they hold no secret, some
// programs need a UTF-8 locale, and some read the user name (for example to
// tag resources with an owner), as they would under the Pulumi CLI.
var passThroughVars = []string{"LANG", "LC_ALL", "LC_CTYPE", "USER", "LOGNAME"}

// childEnv is the environment of a program or a build, built from scratch
// (D19). Only PATH, the locale and the user name are inherited from the
// scanner's environment, and HOME and TMPDIR point to an empty directory of
// the evaluation, so that SDKs and tools do not pick up credentials or
// configuration by accident. This is not isolation: the program runs with the
// scanner's user, filesystem and network access, and can still read them (for
// example the scanner's environment under /proc on Linux, or the real home
// directory).
type childEnv map[string]string

func newChildEnv(home, tmp string) childEnv {
	env := childEnv{"HOME": home, "TMPDIR": tmp, "PATH": os.Getenv("PATH")}
	if env["PATH"] == "" {
		env["PATH"] = defaultPath
	}
	for _, k := range passThroughVars {
		if v, ok := os.LookupEnv(k); ok {
			env[k] = v
		}
	}
	return env
}

func (e childEnv) prependPath(dir string) {
	e["PATH"] = dir + string(os.PathListSeparator) + e["PATH"]
}

// list returns the environment as sorted KEY=value entries.
func (e childEnv) list() []string {
	out := make([]string, 0, len(e))
	for k, v := range e {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

func (e childEnv) clone() childEnv {
	out := make(childEnv, len(e))
	for k, v := range e {
		out[k] = v
	}
	return out
}

// withPulumi adds the variables the SDKs read to reach the fake engine.
func (e childEnv) withPulumi(addr string, p *Project, stack string, cfg *stackConfig) childEnv {
	out := e.clone()
	out["PULUMI_MONITOR"] = addr
	out["PULUMI_ENGINE"] = addr
	out["PULUMI_PROJECT"] = p.Name
	out["PULUMI_STACK"] = stack
	out["PULUMI_ORGANIZATION"] = "organization"
	out["PULUMI_DRY_RUN"] = "true"
	out["PULUMI_PARALLEL"] = strconv.Itoa(parallelism)
	out["PULUMI_CONFIG"] = cfg.configJSON()
	out["PULUMI_CONFIG_SECRET_KEYS"] = cfg.secretKeysJSON()
	out["PULUMI_ROOT_DIRECTORY"] = p.Dir
	return out
}

// withPython sets up a virtual environment, keeping the checkout clean
// (no __pycache__) and ignoring the user site directory.
func (e childEnv) withPython(venv string) childEnv {
	out := e.clone()
	if venv != "" {
		out["VIRTUAL_ENV"] = venv
		out.prependPath(filepath.Join(venv, "bin"))
	}
	out["PYTHONDONTWRITEBYTECODE"] = "1"
	out["PYTHONNOUSERSITE"] = "1"
	out["PYTHONUNBUFFERED"] = "1"
	return out
}

const off = "off"

// goSettings are the Go toolchain settings of a build: no network, no
// toolchain switch, the caches prepared beforehand (D19), and the project's
// workspace only when it is inside the scan root.
type goSettings struct {
	modCache string
	cache    string
	path     string
	work     string // go.work to use, "" for none
	vendored bool
}

func (e childEnv) withGo(g goSettings) childEnv {
	out := e.clone()
	out["GOPROXY"] = off
	out["GOTOOLCHAIN"] = "local"
	out["GOWORK"] = off
	if g.work != "" {
		out["GOWORK"] = g.work
	}
	out["GOSUMDB"] = off
	out["GOENV"] = off
	out["GOTELEMETRY"] = off
	out["CGO_ENABLED"] = "0"
	out["GOMODCACHE"] = g.modCache
	out["GOCACHE"] = g.cache
	out["GOPATH"] = g.path
	// -mod=readonly would disable vendor/, so vendored modules use -mod=vendor.
	if g.vendored {
		out["GOFLAGS"] = "-mod=vendor"
	} else {
		out["GOFLAGS"] = "-mod=readonly"
	}
	return out
}

// defaultGoCaches are the scanner's own Go caches, used when none is given.
func defaultGoCaches() (modCache, cache string) {
	modCache = os.Getenv("GOMODCACHE")
	if modCache == "" {
		gopath := os.Getenv("GOPATH")
		if gopath == "" {
			if home, err := os.UserHomeDir(); err == nil {
				gopath = filepath.Join(home, "go")
			}
		}
		if gopath != "" {
			modCache = filepath.Join(filepath.SplitList(gopath)[0], "pkg", "mod")
		}
	}
	cache = os.Getenv("GOCACHE")
	if cache == "" {
		if dir, err := os.UserCacheDir(); err == nil {
			cache = filepath.Join(dir, "go-build")
		}
	}
	return modCache, cache
}
