package kustomize

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/resolver/sandbox"
	krusty "sigs.k8s.io/kustomize/api/krusty"
	kustypes "sigs.k8s.io/kustomize/api/types"
)

// helperEnvVar: set by renderWithTimeout when re-execing a test binary (no CLI
// binary). Production uses `internal kustomize-render` instead.
const helperEnvVar = "GO_WANT_KUSTOMIZE_RENDER_HELPER"

// helperSleepEnvVar: test-only delay before stdin handling (timeout regression).
const helperSleepEnvVar = "KUSTOMIZE_HELPER_SLEEP_MS"

// init runs the stdin helper when helperEnvVar=1 so stdout stays clean before
// the test framework runs. No-op in normal/production runs.
func init() {
	if os.Getenv(helperEnvVar) != "1" {
		return
	}
	if sleepMs := os.Getenv(helperSleepEnvVar); sleepMs != "" {
		if n, err := strconv.Atoi(sleepMs); err == nil && n > 0 {
			time.Sleep(time.Duration(n) * time.Millisecond)
		}
	}
	_ = RunHelperFromStdin()
	os.Exit(0)
}

// helperRequest is the JSON body on stdin for one kustomize build.
type helperRequest struct {
	BuildRoot  string `json:"build_root"`
	RunFSRoot  string `json:"run_fs_root"`
	StrictLoad bool   `json:"strict_load"`
}

// buildResult is JSON on stdout; render errors use Err (timeouts/crashes are parent-side).
type buildResult struct {
	YAML string `json:"yaml"`
	Err  string `json:"err,omitempty"`
}

// RunHelperFromStdin is the `internal kustomize-render` entrypoint: stdin JSON
// request, stdout JSON result; render failures are encoded in buildResult.Err.
func RunHelperFromStdin() error {
	body, err := io.ReadAll(os.Stdin)
	if err != nil {
		return writeHelperResult(buildResult{Err: fmt.Sprintf("read stdin: %v", err)})
	}
	var req helperRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return writeHelperResult(buildResult{Err: fmt.Sprintf("decode helper request: %v", err)})
	}
	return writeHelperResult(helperRender(req.BuildRoot, req.RunFSRoot, req.StrictLoad))
}

func writeHelperResult(r buildResult) error {
	return json.NewEncoder(os.Stdout).Encode(r)
}

// helperRender runs krusty in-process (shared by CLI subcommand and test re-exec).
func helperRender(buildRoot, runFSRoot string, strictLoad bool) buildResult {
	opts := krusty.MakeDefaultOptions()
	if strictLoad {
		opts.LoadRestrictions = kustypes.LoadRestrictionsRootOnly
	} else {
		opts.LoadRestrictions = kustypes.LoadRestrictionsNone
	}
	opts.PluginConfig = kustypes.DisabledPluginConfig()
	opts.PluginConfig.HelmConfig.Enabled = false
	k := krusty.MakeKustomizer(opts)
	runFS, err := sandbox.NewBoundedFS(runFSRoot)
	if err != nil {
		return buildResult{Err: err.Error()}
	}
	rm, err := k.Run(runFS, buildRoot)
	if err != nil {
		return buildResult{Err: err.Error()}
	}
	yamlOut, err := rm.AsYaml()
	if err != nil {
		return buildResult{Err: err.Error()}
	}
	return buildResult{YAML: string(yamlOut)}
}
