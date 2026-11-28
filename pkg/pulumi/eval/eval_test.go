/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package eval

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/pulumi/capture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func realPath(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	require.NoError(t, err)
	return r
}

func evaluate(t *testing.T, dir string, opts *Options) []capture.Document {
	t.Helper()
	docs, err := Evaluate(context.Background(), dir, opts)
	require.NoError(t, err)
	return docs
}

func single(t *testing.T, docs []capture.Document) capture.Document {
	t.Helper()
	require.Len(t, docs, 1)
	return docs[0]
}

// TestChildEnvironment checks D19: the program sees an environment built from
// scratch, without the scanner's tokens and credentials.
func TestChildEnvironment(t *testing.T) {
	skipWithoutProcessGroups(t)
	for _, k := range []string{
		"DD_JWT_TOKEN", "DD_API_KEY", "DD_APP_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"GOOGLE_APPLICATION_CREDENTIALS", "AZURE_CLIENT_SECRET", "ARM_CLIENT_SECRET", "GITHUB_TOKEN",
		"PULUMI_ACCESS_TOKEN", "PULUMI_CONFIG_PASSPHRASE", "SOME_UNRELATED_VARIABLE",
	} {
		t.Setenv(k, "must-not-leak")
	}
	t.Setenv("USER", "someone")
	t.Setenv("LANG", "C.UTF-8")
	dir := helperProject(t, "env", nil)
	doc := single(t, evaluate(t, dir, nil))
	require.Equal(t, capture.StatusEvaluated, doc.Result.Status, doc.Result.Message)
	require.Len(t, doc.Resources, 1)

	env, ok := doc.Resources[0].Inputs["env"].(map[string]any)
	require.True(t, ok)
	for k, v := range env {
		assert.NotEqual(t, "must-not-leak", v, "%s leaked into the program environment", k)
		assert.False(t, strings.HasPrefix(k, "DD_") || strings.HasPrefix(k, "AWS_") || strings.HasPrefix(k, "GOOGLE_") ||
			strings.HasPrefix(k, "AZURE_") || strings.HasPrefix(k, "ARM_") || strings.HasSuffix(k, "_TOKEN"), "unexpected variable %s", k)
	}
	for _, k := range []string{"PATH", "HOME", "TMPDIR", "PULUMI_MONITOR", "PULUMI_ENGINE", "PULUMI_PROJECT", "PULUMI_STACK",
		"PULUMI_DRY_RUN", "PULUMI_CONFIG", "PULUMI_CONFIG_SECRET_KEYS", "PULUMI_ROOT_DIRECTORY"} {
		assert.Contains(t, env, k)
	}
	assert.Equal(t, os.Getenv("PATH"), env["PATH"])
	assert.Equal(t, "someone", env["USER"], "the user name and the locale are passed through")
	assert.Equal(t, "C.UTF-8", env["LANG"])
	assert.Equal(t, "true", env["PULUMI_DRY_RUN"])
	assert.NotEqual(t, os.Getenv("HOME"), env["HOME"], "HOME is an empty directory of the evaluation")
	assert.Equal(t, realPath(t, dir), realPath(t, doc.Resources[0].Inputs["cwd"].(string)), "the program runs in the project directory")
}

// TestTimeoutKillsProcessGroup checks that a timeout kills the program and what it started.
func TestTimeoutKillsProcessGroup(t *testing.T) {
	skipWithoutProcessGroups(t)
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("no sleep command")
	}
	dir := helperProject(t, "sleep", nil)
	start := time.Now()
	doc := single(t, evaluate(t, dir, &Options{Timeout: 3 * time.Second}))
	assert.Less(t, time.Since(start), 20*time.Second)
	assert.Equal(t, capture.StatusFailed, doc.Result.Status)
	assert.Equal(t, capture.ReasonTimeout, doc.Result.Reason)

	require.Len(t, doc.Resources, 1, "resources declared before the timeout are kept")
	pid, err := strconv.Atoi(doc.Resources[0].Inputs["pid"].(string))
	require.NoError(t, err)
	assert.Eventually(t, func() bool { return processGone(pid) }, 5*time.Second, 50*time.Millisecond,
		"the program's child %d survived the timeout", pid)
}

// TestCancelKillsProcessGroup checks that canceling the evaluation, as
// pulumi-eval does on Ctrl-C, kills the program and what it started, removes
// the evaluation's directory and stops with the context's error.
func TestCancelKillsProcessGroup(t *testing.T) {
	skipWithoutProcessGroups(t)
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("no sleep command")
	}
	dir := helperProject(t, "sleep", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := Evaluate(ctx, dir, nil)
		done <- err
	}()

	pidFile := filepath.Join(dir, "sleeper.pid")
	require.Eventually(t, func() bool { _, err := os.Stat(pidFile); return err == nil }, 20*time.Second, 50*time.Millisecond)
	b, err := os.ReadFile(pidFile)
	require.NoError(t, err)
	pidLine, tmpDir, ok := strings.Cut(string(b), "\n")
	require.True(t, ok)
	pid, err := strconv.Atoi(pidLine)
	require.NoError(t, err)

	cancel()
	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(20 * time.Second):
		t.Fatal("the evaluation did not stop after cancellation")
	}
	assert.Eventually(t, func() bool { return processGone(pid) }, 5*time.Second, 50*time.Millisecond,
		"the program's child %d survived the cancellation", pid)
	assert.NoDirExists(t, filepath.Dir(tmpDir), "the evaluation's directory is removed")
}

// TestChildHoldingOutputDoesNotFail checks that a program that exits
// successfully while its child still holds the output is evaluated, and that
// the child is killed.
func TestChildHoldingOutputDoesNotFail(t *testing.T) {
	skipWithoutProcessGroups(t)
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("no sleep command")
	}
	doc := single(t, evaluate(t, helperProject(t, "orphan", nil), nil))
	require.Equal(t, capture.StatusEvaluated, doc.Result.Status, doc.Result.Message)
	require.Len(t, doc.Resources, 1)
	pid, err := strconv.Atoi(doc.Resources[0].Inputs["pid"].(string))
	require.NoError(t, err)
	assert.Eventually(t, func() bool { return processGone(pid) }, 5*time.Second, 50*time.Millisecond,
		"the program's child %d survived", pid)
}

// TestProgramRunsInMainDirectory checks that the program runs where the
// Pulumi CLI runs it when Pulumi.yaml sets main: in that directory, or in the
// directory of that file. A main that does not exist leaves the program in the
// project directory, where it reports the missing main itself.
func TestProgramRunsInMainDirectory(t *testing.T) {
	skipWithoutProcessGroups(t)
	exe, err := os.Executable()
	require.NoError(t, err)
	for main, want := range map[string]string{"src/": "src", "app/program.py": "app", "missing/": "."} {
		t.Run(main, func(t *testing.T) {
			dir := helperProject(t, "env", map[string]string{
				"Pulumi.yaml": fmt.Sprintf("name: %senv\nmain: %s\nruntime:\n  name: go\n  options:\n    binary: %s\n",
					helperPrefix, main, exe),
				"src/.keep":      "",
				"app/program.py": "",
			})
			doc := single(t, evaluate(t, dir, nil))
			require.Equal(t, capture.StatusEvaluated, doc.Result.Status, doc.Result.Message)
			assert.Equal(t, realPath(t, filepath.Join(dir, want)), realPath(t, doc.Resources[0].Inputs["cwd"].(string)))
			env := doc.Resources[0].Inputs["env"].(map[string]any)
			assert.Equal(t, realPath(t, dir), realPath(t, env["PULUMI_ROOT_DIRECTORY"].(string)), "the root stays the project directory")
		})
	}
}

// TestPythonRunsInMainDirectory checks the working directory given to the
// Python launcher when Pulumi.yaml sets main.
func TestPythonRunsInMainDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"src/__main__.py": ""})
	l := &pythonLauncher{python: "python3", script: "launcher"}
	for main, want := range map[string]string{
		"": dir, "src": filepath.Join(dir, "src"), "src/__main__.py": filepath.Join(dir, "src"), "missing": dir,
	} {
		p := &Project{Dir: dir, Name: "app", Main: main}
		c := l.command(p, "dev", "127.0.0.1:1", childEnv{})
		assert.Equal(t, want, c.dir, "main %q", main)
		assert.Equal(t, want, argAfter(c.argv, "--pwd"), "main %q", main)
		assert.Equal(t, dir, argAfter(c.argv, "--root_directory"), "main %q", main)
	}
}

func argAfter(argv []string, flag string) string {
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == flag {
			return argv[i+1]
		}
	}
	return ""
}

func TestResourceCap(t *testing.T) {
	skipWithoutProcessGroups(t)
	doc := single(t, evaluate(t, helperProject(t, "many", nil), &Options{MaxResources: 25}))
	assert.Equal(t, capture.StatusFailed, doc.Result.Status)
	assert.Equal(t, capture.ReasonResourceCap, doc.Result.Reason)
	assert.Len(t, doc.Resources, 25)
}

// TestConfigRetry checks D18: a missing key gets a placeholder typed from the
// accessor the program uses, and the evaluation is marked partial.
func TestConfigRetry(t *testing.T) {
	skipWithoutProcessGroups(t)
	dir := helperProject(t, "config", map[string]string{
		"__main__.py": "import pulumi\ncount = pulumi.Config().require_int(\"count\")\n",
		"Pulumi.dev.yaml": "config:\n  evaltest-config:password:\n    secure: AAABAKqm\n" +
			"  aws:region: eu-west-1\n  evaltest-config:tags:\n    team: data\n",
	})
	doc := single(t, evaluate(t, dir, nil))
	require.Equal(t, capture.StatusEvaluated, doc.Result.Status, doc.Result.Message)
	assert.True(t, doc.Result.Partial)
	assert.Equal(t, 2, doc.Result.Attempts)
	assert.Equal(t, "dev", doc.Stack)
	assert.False(t, doc.SyntheticStack)
	require.Len(t, doc.Resources, 1)
	assert.Equal(t, "1", doc.Resources[0].Inputs["count"], "typed from require_int")
	assert.Equal(t, `["evaltest-config:password"]`, doc.Resources[0].Inputs["secretKeys"])

	assert.Equal(t, []string{"evaltest-config:count"}, doc.Config.Placeholders)
	assert.Equal(t, []string{"evaltest-config:password"}, doc.Config.Secrets)
	assert.NotContains(t, doc.Config.Values, "evaltest-config:password", "secret values are not in the capture")
	assert.Equal(t, "eu-west-1", doc.Config.Values["aws:region"])
	assert.Equal(t, `{"team":"data"}`, doc.Config.Values["evaltest-config:tags"], "structured values are passed as JSON")
	assert.NotContains(t, doc.Config.ProviderDefaults, "aws:region", "set by the stack")
	assert.Contains(t, doc.Config.ProviderDefaults, "gcp:project")
}

func TestProgramErrorClassified(t *testing.T) {
	skipWithoutProcessGroups(t)
	doc := single(t, evaluate(t, helperProject(t, "fail", nil), nil))
	assert.Equal(t, capture.StatusFailed, doc.Result.Status)
	assert.Equal(t, capture.ReasonProgramError, doc.Result.Reason)
	assert.Equal(t, capture.DetailSDKAPIMismatch, doc.Result.Detail)
	assert.Contains(t, doc.Result.Message, "interface conversion")
}

// TestCapabilityProbeIsNotUnsupportedRPC checks that the SDKs' startup probe,
// answered as unimplemented, does not make every failure engine_unsupported_rpc.
func TestCapabilityProbeIsNotUnsupportedRPC(t *testing.T) {
	skipWithoutProcessGroups(t)
	doc := single(t, evaluate(t, helperProject(t, "probe-then-fail", nil), nil))
	assert.Equal(t, capture.StatusFailed, doc.Result.Status)
	assert.Equal(t, capture.ReasonProgramError, doc.Result.Reason)
	assert.Empty(t, doc.Result.Detail)
}

// TestScanRootRelativePaths checks that paths are relative to the scan root.
func TestScanRootRelativePaths(t *testing.T) {
	skipWithoutProcessGroups(t)
	dir := helperProject(t, "env", nil)
	base := filepath.Base(dir)
	doc := single(t, evaluate(t, dir, &Options{Root: filepath.Dir(dir)}))
	require.Equal(t, capture.StatusEvaluated, doc.Result.Status, doc.Result.Message)
	assert.Equal(t, base, doc.ProjectDir)
	require.NotNil(t, doc.Resources[0].Source)
	assert.Equal(t, base+"/main.go", doc.Resources[0].Source.Path)
	assert.Equal(t, 7, doc.Resources[0].Source.Line)

	doc = single(t, evaluate(t, dir, nil))
	assert.Equal(t, ".", doc.ProjectDir)
	assert.Equal(t, "main.go", doc.Resources[0].Source.Path)

	_, err := Evaluate(context.Background(), dir, &Options{Root: t.TempDir()})
	assert.ErrorContains(t, err, "not under the scan root")
}

func TestUnsupportedRuntime(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"Pulumi.yaml": "name: web\nruntime: nodejs\n", "Pulumi.prod.yaml": "config: {}\n"})
	doc := single(t, evaluate(t, dir, nil))
	assert.Equal(t, capture.StatusSkipped, doc.Result.Status)
	assert.Equal(t, capture.ReasonUnsupportedRuntime, doc.Result.Reason)
	assert.Equal(t, "pulumi project not evaluated: unsupported runtime nodejs", doc.Result.Message)
	assert.Equal(t, "prod", doc.Stack)
}

func TestWindowsExecutesNothing(t *testing.T) {
	if osSupported {
		t.Skip("only on an OS without evaluation support")
	}
	doc := single(t, evaluate(t, helperProject(t, "env", nil), nil))
	assert.Equal(t, capture.StatusSkipped, doc.Result.Status)
	assert.Equal(t, capture.ReasonOSUnsupported, doc.Result.Reason)
	assert.Equal(t, "pulumi evaluation not supported on Windows", doc.Result.Message)
	assert.Empty(t, doc.Resources)
}

func TestPythonRuntimeMissing(t *testing.T) {
	skipWithoutProcessGroups(t)
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"Pulumi.yaml": "name: app\nruntime: python\n", "__main__.py": ""})
	doc := single(t, evaluate(t, dir, &Options{Python: filepath.Join(dir, "no-such-python")}))
	assert.Equal(t, capture.StatusFailed, doc.Result.Status)
	assert.Equal(t, capture.ReasonRuntimeMissing, doc.Result.Reason)
	assert.True(t, doc.SyntheticStack)
	assert.Equal(t, capture.SyntheticStack, doc.Stack)
}

// TestPythonDepsMissing runs a Python program whose interpreter has no Pulumi SDK.
func TestPythonDepsMissing(t *testing.T) {
	skipWithoutProcessGroups(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3")
	}
	if exec.Command(python, "-c", "import pulumi").Run() == nil { //nolint:gosec // test helper
		t.Skip("python3 has the Pulumi SDK installed")
	}
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"Pulumi.yaml": "name: app\nruntime: python\n", "__main__.py": "import pulumi\n"})
	doc := single(t, evaluate(t, dir, &Options{Python: python}))
	assert.Equal(t, capture.StatusFailed, doc.Result.Status)
	assert.Equal(t, capture.ReasonDepsMissing, doc.Result.Reason, doc.Result.Message)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 2, "nothing is written into the project (no __pycache__)")
}

func goToolchain(t *testing.T) (gotool, gocache string) {
	t.Helper()
	gotool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain")
	}
	out, err := exec.Command(gotool, "env", "GOCACHE").Output() //nolint:gosec // test helper
	require.NoError(t, err)
	return gotool, strings.TrimSpace(string(out))
}

func copyFixture(t *testing.T, name string) string {
	t.Helper()
	dst := t.TempDir()
	src := filepath.Join("testdata", name)
	require.NoError(t, filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		b, err := os.ReadFile(path) //nolint:gosec // test fixture
		if err != nil {
			return err
		}
		writeFiles(t, dst, map[string]string{filepath.ToSlash(rel): string(b)})
		return nil
	}))
	return dst
}

// TestGoDepsMissing checks D19: with an empty module cache the build fails as
// deps_missing and nothing is downloaded.
func TestGoDepsMissing(t *testing.T) {
	skipWithoutProcessGroups(t)
	gotool, gocache := goToolchain(t)
	modCache := t.TempDir()
	doc := single(t, evaluate(t, copyFixture(t, "go-deps-missing"), &Options{Go: gotool, GoModCache: modCache, GoCache: gocache}))
	assert.Equal(t, capture.StatusFailed, doc.Result.Status)
	assert.Equal(t, capture.ReasonDepsMissing, doc.Result.Reason, doc.Result.Message)
	entries, err := os.ReadDir(modCache)
	require.NoError(t, err)
	assert.Empty(t, entries, "the module cache stays empty: nothing was downloaded")
}

// TestGoVendored checks D19: a vendored program builds with an empty module cache.
func TestGoVendored(t *testing.T) {
	skipWithoutProcessGroups(t)
	gotool, gocache := goToolchain(t)
	doc := single(t, evaluate(t, copyFixture(t, "go-vendored"), &Options{Go: gotool, GoModCache: t.TempDir(), GoCache: gocache}))
	assert.Equal(t, capture.StatusEvaluated, doc.Result.Status, doc.Result.Message)
	assert.Empty(t, doc.Resources)
}

// TestGoWorkspace checks the D19 workspace rule: a go.work between the program
// and the scan root is used, one above the scan root is not.
func TestGoWorkspace(t *testing.T) {
	skipWithoutProcessGroups(t)
	gotool, gocache := goToolchain(t)
	root := copyFixture(t, "go-workspace")
	app := filepath.Join(root, "app")

	doc := single(t, evaluate(t, app, &Options{Root: root, Go: gotool, GoModCache: t.TempDir(), GoCache: gocache}))
	assert.Equal(t, capture.StatusEvaluated, doc.Result.Status, doc.Result.Message)
	assert.Equal(t, "app", doc.ProjectDir)

	doc = single(t, evaluate(t, app, &Options{Root: app, Go: gotool, GoModCache: t.TempDir(), GoCache: gocache}))
	assert.Equal(t, capture.StatusFailed, doc.Result.Status, "the go.work above the scan root is ignored")
	assert.Equal(t, capture.ReasonDepsMissing, doc.Result.Reason, doc.Result.Message)

	// Through a symbolic link (macOS's /var is one), the workspace still applies.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(root, link); err != nil {
		t.Skipf("symbolic links are not supported: %v", err)
	}
	doc = single(t, evaluate(t, filepath.Join(link, "app"), &Options{Root: link, Go: gotool, GoModCache: t.TempDir(), GoCache: gocache}))
	assert.Equal(t, capture.StatusEvaluated, doc.Result.Status, doc.Result.Message)
}

func TestFindUpStopsAtRoot(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{"go.mod": "module x\n", "a/b/main.go": ""})
	assert.Equal(t, root, findUp(filepath.Join(root, "a", "b"), root, "go.mod"))
	assert.Empty(t, findUp(filepath.Join(root, "a", "b"), filepath.Join(root, "a"), "go.mod"), "not above the root")
	assert.Empty(t, findUp(filepath.Dir(root), root, "go.mod"), "nothing outside the root")
}

func TestStacks(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"Pulumi.yaml":             "name: app\nruntime:\n  name: python\n  options:\n    virtualenv: venv\nmain: src/\nstackConfigDir: stacks\n",
		"stacks/Pulumi.prod.yaml": "config:\n  app:size: 3\n",
		"stacks/Pulumi.dev.yml":   "config: {}\n",
		"Pulumi.ignored.yaml":     "config: {}\n",
	})
	p, err := LoadProject(dir)
	require.NoError(t, err)
	assert.Equal(t, "python", p.Runtime)
	assert.Equal(t, "venv", p.option("virtualenv"))
	assert.Equal(t, "src/", p.Main)
	stacks, err := p.Stacks()
	require.NoError(t, err)
	require.Len(t, stacks, 2)
	assert.Equal(t, "dev", stacks[0].Name)
	assert.Equal(t, "prod", stacks[1].Name)
	assert.Equal(t, 3, stacks[1].Config["app:size"])

	_, err = selectStacks(stacks, []string{"staging"})
	assert.Error(t, err)

	_, err = LoadProject(t.TempDir())
	assert.Error(t, err)
}

func TestCaptureIsJSON(t *testing.T) {
	skipWithoutProcessGroups(t)
	docs := evaluate(t, helperProject(t, "env", nil), nil)
	b, err := json.Marshal(docs)
	require.NoError(t, err)
	var back []capture.Document
	require.NoError(t, json.Unmarshal(b, &back))
	assert.Equal(t, capture.FormatVersion, back[0].FormatVersion)
}
