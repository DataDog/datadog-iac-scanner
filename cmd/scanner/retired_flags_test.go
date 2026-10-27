package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cli "github.com/urfave/cli/v3"
)

func retiredFlagNames(flags []cli.Flag) []string {
	names := make([]string, 0, len(flags))
	for _, flag := range flags {
		names = append(names, flag.Names()[0])
	}
	return names
}

func TestRetiredTimeoutFlagIsIgnored(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	prev := log.Logger
	prevLevel := zerolog.GlobalLevel()
	t.Cleanup(func() {
		log.Logger = prev
		zerolog.SetGlobalLevel(prevLevel)
	})
	log.Logger = zerolog.New(&buf)

	cmd := &cli.Command{
		Name: "test",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "log-format", Value: "json"},
			&cli.StringFlag{Name: "log-level", Value: "error"},
		},
		Before: applyGlobalOptions,
		Commands: []*cli.Command{
			{
				Name:  "scan",
				Flags: append([]cli.Flag{&cli.StringSliceFlag{Name: "path"}}, retiredScanFlags()...),
				Action: func(_ context.Context, c *cli.Command) error {
					assert.Empty(t, c.Args().Slice())
					return nil
				},
			},
		},
	}

	require.NoError(t, cmd.Run(context.Background(), []string{
		"test",
		"--log-level", "warn",
		"scan",
		"--path", "/tmp",
		"--timeout", "60",
	}))
	assert.Contains(t, buf.String(), `"flag":"timeout"`)
	assert.Contains(t, buf.String(), "ignoring retired flag")
}

func TestRetiredScanOnlyFlagsAreNotOnServe(t *testing.T) {
	t.Parallel()

	serve := &cli.Command{Name: "serve", Flags: retiredServeFlags()}

	err := serve.Run(context.Background(), []string{"serve", "--timeout", "60"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "flag provided but not defined")
}

func TestRetiredFlagComposition(t *testing.T) {
	t.Parallel()

	shared := retiredFlagNames(sharedRetiredFlags())
	scanOnly := retiredFlagNames(retiredScanOnlyFlags())
	serveOnly := retiredFlagNames(retiredServeOnlyFlags())
	scan := retiredFlagNames(retiredScanFlags())
	serve := retiredFlagNames(retiredServeFlags())

	for _, name := range shared {
		assert.Contains(t, scan, name)
		assert.Contains(t, serve, name)
	}
	for _, name := range scanOnly {
		assert.Contains(t, scan, name)
		assert.NotContains(t, serve, name)
	}
	for _, name := range serveOnly {
		assert.Contains(t, serve, name)
		assert.NotContains(t, scan, name)
	}
}

func TestRetiredFlagsAreHidden(t *testing.T) {
	t.Parallel()

	assert.Empty(t, (&cli.Command{Flags: retiredScanFlags()}).VisibleFlags())
	assert.Empty(t, (&cli.Command{Flags: retiredServeFlags()}).VisibleFlags())
}

func TestUnknownXFlagFailsAtParseTime(t *testing.T) {
	t.Parallel()

	cmd := &cli.Command{
		Name:  "scan",
		Flags: append([]cli.Flag{&cli.StringSliceFlag{Name: "path"}}, retiredScanFlags()...),
		Action: func(_ context.Context, _ *cli.Command) error {
			return nil
		},
	}

	err := cmd.Run(context.Background(), []string{"scan", "--x-blabla", "1234", "--path", "."})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "flag provided but not defined")
}

// Deployments that still pass the retired flags, in any boolean spelling,
// must keep starting.
func TestRetiredParallelParsingAndRuleIsolationFlagsAreAccepted(t *testing.T) {
	t.Parallel()

	for name, flags := range map[string][]cli.Flag{
		"scan":  retiredScanFlags(),
		"serve": retiredServeFlags(),
	} {
		for _, args := range [][]string{
			{"--x-parallelparsing"},
			{"--x-parallelparsing=false"},
		} {
			cmd := &cli.Command{Name: name, Flags: flags}
			require.NoError(t, cmd.Run(context.Background(), append([]string{name}, args...)), "%s %v", name, args)
		}
	}

	scan := &cli.Command{Name: "scan", Flags: retiredScanFlags()}
	require.NoError(t, scan.Run(context.Background(), []string{"scan", "--x-disable-rule-isolation"}))
}
