package main

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cli "github.com/urfave/cli/v3"
)

func TestUnknownExperimentalFlagName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		err     error
		want    string
		wantOK  bool
	}{
		{
			name:   "unknown x flag",
			err:    fmt.Errorf("flag provided but not defined: -x-removed-flag"),
			want:   "x-removed-flag",
			wantOK: true,
		},
		{
			name:   "unknown real flag",
			err:    fmt.Errorf("flag provided but not defined: -pathh"),
			wantOK: false,
		},
		{
			name:   "other error",
			err:    fmt.Errorf("something else"),
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := unknownExperimentalFlagName(tt.err)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRemoveFlagArg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		args     []string
		flagName string
		want     []string
	}{
		{
			name:     "long boolean flag",
			args:     []string{"scan", "--x-removed", "--path", "/tmp"},
			flagName: "x-removed",
			want:     []string{"scan", "--path", "/tmp"},
		},
		{
			name:     "long flag with value",
			args:     []string{"scan", "--x-removed=false", "--path", "/tmp"},
			flagName: "x-removed",
			want:     []string{"scan", "--path", "/tmp"},
		},
		{
			name:     "short form",
			args:     []string{"scan", "-x-removed", "--path", "/tmp"},
			flagName: "x-removed",
			want:     []string{"scan", "--path", "/tmp"},
		},
		{
			name:     "paired value",
			args:     []string{"scan", "--x-removed-manifest", "/tmp/manifest.json", "--path", "/tmp"},
			flagName: "x-removed-manifest",
			want:     []string{"scan", "--path", "/tmp"},
		},
		{
			name:     "does not consume following flag",
			args:     []string{"scan", "--x-removed", "--path", "/tmp"},
			flagName: "x-removed",
			want:     []string{"scan", "--path", "/tmp"},
		},
		{
			name:     "does not consume following short flag",
			args:     []string{"scan", "--x-removed", "-p", "/tmp"},
			flagName: "x-removed",
			want:     []string{"scan", "-p", "/tmp"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, removeFlagArg(tt.args, tt.flagName))
		})
	}
}

func TestRunCLI_IgnoresUnknownExperimentalFlags(t *testing.T) {
	t.Parallel()

	cmd := &cli.Command{
		Name: "test",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "path"},
		},
		Action: func(_ context.Context, _ *cli.Command) error {
			return nil
		},
	}
	applyUsageErrorHandlers(cmd)

	err := runCLI(context.Background(), cmd, []string{"test", "--path", "/tmp", "--x-removed-flag"})
	require.NoError(t, err)
}

func TestRunCLI_RejectsUnknownRealFlags(t *testing.T) {
	t.Parallel()

	cmd := &cli.Command{
		Name: "test",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "path"},
		},
		Action: func(_ context.Context, _ *cli.Command) error {
			return nil
		},
	}
	applyUsageErrorHandlers(cmd)

	err := runCLI(context.Background(), cmd, []string{"test", "--pathh", "/tmp"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "flag provided but not defined")
}

func TestUsageErrorHandler_ShowsSubcommandHelp(t *testing.T) {
	t.Parallel()

	var help bytes.Buffer
	scan := &cli.Command{
		Name: "scan",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "path", Aliases: []string{"p"}},
		},
		Action: func(_ context.Context, _ *cli.Command) error {
			return nil
		},
	}
	root := &cli.Command{
		Name:     "datadog-iac-scanner",
		Commands: []*cli.Command{scan},
		Writer:   &help,
		ErrWriter: &help,
	}
	applyUsageErrorHandlers(root)

	err := runCLI(context.Background(), root, []string{
		"datadog-iac-scanner",
		"scan",
		"--pathh",
		"/tmp",
	})
	require.Error(t, err)
	assert.Contains(t, help.String(), "scan")
	assert.Contains(t, help.String(), "--path")
}

func TestRunCLI_IgnoresMultipleUnknownExperimentalFlags(t *testing.T) {
	t.Parallel()

	cmd := &cli.Command{
		Name: "test",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "path"},
		},
		Action: func(_ context.Context, _ *cli.Command) error {
			return nil
		},
	}
	applyUsageErrorHandlers(cmd)

	err := runCLI(context.Background(), cmd, []string{
		"test",
		"--path", "/tmp",
		"--x-first-removed",
		"--x-second-removed=true",
	})
	require.NoError(t, err)
}

func TestRunCLI_IgnoresUnknownExperimentalFlagWithPairedValue(t *testing.T) {
	t.Parallel()

	cmd := &cli.Command{
		Name: "test",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "path"},
		},
		Action: func(_ context.Context, _ *cli.Command) error {
			return nil
		},
	}
	applyUsageErrorHandlers(cmd)

	err := runCLI(context.Background(), cmd, []string{
		"test",
		"--path", "/tmp",
		"--x-removed-manifest", "/tmp/manifest.json",
	})
	require.NoError(t, err)
}
