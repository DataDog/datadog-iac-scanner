/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/constants"
	"github.com/DataDog/datadog-iac-scanner/pkg/pulumi/capture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cli "github.com/urfave/cli/v3"
)

func runPulumiEval(t *testing.T, args ...string) error {
	t.Helper()
	app := &cli.Command{Name: "datadog-iac-scanner", Commands: []*cli.Command{pulumiEvalAction}}
	return app.Run(context.Background(), append([]string{"datadog-iac-scanner", "pulumi-eval"}, args...))
}

func TestPulumiEvalIsHidden(t *testing.T) {
	assert.True(t, pulumiEvalAction.Hidden)
	assert.Contains(t, pulumiEvalAction.Usage, "executes the project's code")
}

func TestPulumiEvalWritesCaptures(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Pulumi.yaml"), []byte("name: web\nruntime: nodejs\n"), 0o600))
	out := filepath.Join(t.TempDir(), "capture.json")

	err := runPulumiEval(t, "--output", out, dir)
	var exit *withExitCodeError
	require.True(t, errors.As(err, &exit), "a stack that is not evaluated gives a non-zero exit code")
	assert.Equal(t, pulumiEvalNotEvaluated, exit.code)
	assert.NoError(t, exit.err, "nothing is printed after the JSON")

	b, err := os.ReadFile(out)
	require.NoError(t, err)
	var docs []capture.Document
	require.NoError(t, json.Unmarshal(b, &docs))
	require.Len(t, docs, 1)
	assert.Equal(t, capture.StatusSkipped, docs[0].Result.Status)
	assert.Equal(t, capture.ReasonUnsupportedRuntime, docs[0].Result.Reason)
	assert.Equal(t, capture.SyntheticStack, docs[0].Stack)
}

func TestPulumiEvalErrors(t *testing.T) {
	var exit *withExitCodeError
	require.True(t, errors.As(runPulumiEval(t), &exit))
	assert.Error(t, exit.err)

	require.True(t, errors.As(runPulumiEval(t, t.TempDir()), &exit), "no Pulumi.yaml")
	assert.ErrorContains(t, exit.err, "no Pulumi.yaml")
}

// TestPulumiEvalInterrupted checks the exit code when the evaluation is
// canceled, as on Ctrl-C.
func TestPulumiEvalInterrupted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nothing is evaluated on Windows")
	}
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Pulumi.yaml"), []byte("name: web\nruntime: python\n"), 0o600))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	app := &cli.Command{Name: "datadog-iac-scanner", Commands: []*cli.Command{pulumiEvalAction}}
	err := app.Run(ctx, []string{"datadog-iac-scanner", "pulumi-eval", "--output", filepath.Join(t.TempDir(), "capture.json"), dir})
	var exit *withExitCodeError
	require.True(t, errors.As(err, &exit))
	assert.Equal(t, constants.SignalInterruptCode, exit.code)
	assert.ErrorIs(t, exit.err, context.Canceled)
}
