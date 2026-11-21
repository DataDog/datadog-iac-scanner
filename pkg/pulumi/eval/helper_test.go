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
	"syscall"
	"testing"
	"time"

	pulumirpc "github.com/pulumi/pulumi/sdk/v3/proto/go"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
)

// The test binary doubles as a fake Pulumi program: run by the Go launcher
// (runtime option "binary"), it talks to the fake engine like an SDK would.
// The behavior is the part of the project name after this prefix.
const helperPrefix = "evaltest-"

func TestMain(m *testing.M) {
	if os.Getenv("PULUMI_MONITOR") != "" && strings.HasPrefix(os.Getenv("PULUMI_PROJECT"), helperPrefix) {
		code := fakeProgram(strings.TrimPrefix(os.Getenv("PULUMI_PROJECT"), helperPrefix))
		// syscall.Exit skips the exit hooks: a test binary built with -cover
		// would otherwise print "warning: GOCOVERDIR not set, no coverage data
		// emitted", which the evaluation classifies as a missing variable.
		syscall.Exit(code)
	}
	os.Exit(m.Run())
}

func fakeProgram(behavior string) int {
	conn, err := grpc.NewClient(os.Getenv("PULUMI_MONITOR"), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = conn.Close() }()
	mon := pulumirpc.NewResourceMonitorClient(conn)
	ctx := context.Background()
	project, stack := os.Getenv("PULUMI_PROJECT"), os.Getenv("PULUMI_STACK")
	root, err := mon.RegisterResource(ctx, &pulumirpc.RegisterResourceRequest{Type: "pulumi:pulumi:Stack", Name: project + "-" + stack})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	register := func(name string, inputs map[string]any) error {
		obj, err := structpb.NewStruct(inputs)
		if err != nil {
			return err
		}
		wd, _ := os.Getwd()
		_, err = mon.RegisterResource(ctx, &pulumirpc.RegisterResourceRequest{
			Type: "test:index:Thing", Name: name, Custom: true, Parent: root.GetUrn(), Object: obj,
			SourcePosition: &pulumirpc.SourcePosition{Uri: "file://" + filepath.ToSlash(filepath.Join(wd, "main.go")), Line: 7},
		})
		return err
	}

	switch behavior {
	case "env":
		env := map[string]any{}
		for _, kv := range os.Environ() {
			k, v, _ := strings.Cut(kv, "=")
			env[k] = v
		}
		wd, _ := os.Getwd()
		return exitOn(register("env", map[string]any{"env": env, "cwd": wd}))
	case "sleep":
		child := exec.Command("sleep", "300")
		if err := child.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := register("sleeper", map[string]any{"pid": strconv.Itoa(child.Process.Pid)}); err != nil {
			return exitOn(err)
		}
		// For a test that cancels the evaluation and gets no document: the
		// child's pid and the program's TMPDIR.
		pidFile := strconv.Itoa(child.Process.Pid) + "\n" + os.Getenv("TMPDIR")
		// Written then renamed, so that the test never reads it half written.
		if err := os.WriteFile("sleeper.pid.tmp", []byte(pidFile), 0o600); err != nil {
			return exitOn(err)
		}
		if err := os.Rename("sleeper.pid.tmp", "sleeper.pid"); err != nil {
			return exitOn(err)
		}
		time.Sleep(10 * time.Minute)
		return 0
	case "orphan":
		// Exits successfully, leaving a child that holds the program's output open.
		child := exec.Command("sleep", "300")
		child.Stdout = os.Stdout
		if err := child.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return exitOn(register("orphan", map[string]any{"pid": strconv.Itoa(child.Process.Pid)}))
	case "many":
		for i := 0; ; i++ {
			if err := register(fmt.Sprintf("r%d", i), map[string]any{}); err != nil {
				return exitOn(err)
			}
		}
	case "config":
		var cfg map[string]string
		_ = json.Unmarshal([]byte(os.Getenv("PULUMI_CONFIG")), &cfg)
		v, ok := cfg["evaltest-config:count"]
		if !ok {
			fmt.Fprintln(os.Stderr, "error: Missing required configuration variable 'evaltest-config:count'")
			return 1
		}
		return exitOn(register("configured", map[string]any{"count": v, "secretKeys": os.Getenv("PULUMI_CONFIG_SECRET_KEYS")}))
	case "fail":
		fmt.Fprintln(os.Stderr, "panic: interface conversion: interface {} is nil, not string")
		return 2
	case "probe-then-fail":
		// The Go and Python SDKs start with this call and fall back on Unimplemented.
		_, _ = mon.GetDeploymentInfo(ctx, &emptypb.Empty{})
		fmt.Fprintln(os.Stderr, "error: program failed")
		return 1
	}
	return 0
}

func exitOn(err error) int {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// helperProject writes a Go project whose program is this test binary.
func helperProject(t *testing.T, behavior string, files map[string]string) string {
	t.Helper()
	exe, err := os.Executable()
	require.NoError(t, err)
	dir := t.TempDir()
	pulumiYAML := fmt.Sprintf("name: %s%s\nruntime:\n  name: go\n  options:\n    binary: %s\n", helperPrefix, behavior, exe)
	writeFiles(t, dir, map[string]string{"Pulumi.yaml": pulumiYAML})
	writeFiles(t, dir, files)
	return dir
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
}

func skipWithoutProcessGroups(t *testing.T) {
	t.Helper()
	if !osSupported {
		t.Skip("evaluation is not supported on this OS")
	}
}
