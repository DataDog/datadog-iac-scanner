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
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/DataDog/datadog-iac-scanner/internal/constants"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/pulumi/capture"
	"github.com/DataDog/datadog-iac-scanner/pkg/pulumi/engine"
	"github.com/DataDog/datadog-iac-scanner/pkg/pulumi/eval"
	cli "github.com/urfave/cli/v3"
)

// pulumiEvalNotEvaluated is the exit code when a stack was not evaluated.
const pulumiEvalNotEvaluated = 1

// pulumiEvalAction is a hidden debug command: it runs one Pulumi project
// against the fake engine and prints the capture documents. It executes the
// project's code.
var pulumiEvalAction = &cli.Command{
	Name:      "pulumi-eval",
	Usage:     "Evaluates a Pulumi project against the fake engine and prints what it declares (executes the project's code)",
	ArgsUsage: "<project-dir>",
	Hidden:    true,
	Description: "The project's code runs with the scanner's user, filesystem and network access. Its environment is\n" +
		"rebuilt so that SDKs do not pick up credentials or configuration by accident, but this is not isolation:\n" +
		"only run this command in a disposable environment that holds no secret and has no network access the\n" +
		"program should not have.",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "root", Usage: "scan root, capture paths are relative to it (default: the project directory)"},
		&cli.StringSliceFlag{Name: "stack", Usage: "stack to evaluate (default: every committed stack, or dd-scan)"},
		&cli.DurationFlag{Name: "timeout", Usage: "time limit per stack", Value: eval.DefaultTimeout},
		&cli.DurationFlag{Name: "build-timeout", Usage: "time limit of a Go build", Value: eval.DefaultBuildTimeout},
		&cli.IntFlag{Name: "max-resources", Usage: "resources recorded per stack", Value: engine.DefaultMaxResources},
		&cli.StringFlag{Name: "python", Usage: "Python interpreter with the project's dependencies"},
		&cli.StringFlag{Name: "go", Usage: "Go toolchain"},
		&cli.StringFlag{Name: "gomodcache", Usage: "prepared Go module cache"},
		&cli.StringFlag{Name: "gocache", Usage: "Go build cache"},
		&cli.StringFlag{Name: "output", Usage: "file to write the JSON to (default: stdout)"},
	},
	Action: pulumiEval,
}

func pulumiEval(ctx context.Context, c *cli.Command) error {
	if c.Args().Len() != 1 {
		return errorWithExitCode(errors.New("pulumi-eval takes one project directory"), constants.EngineErrorCode)
	}
	root, err := getAbsolutePath(c.String("root"))
	if err != nil {
		return err
	}
	// The program runs in its own process group, out of reach of the
	// terminal's Ctrl-C and hangup: canceling the evaluation is what kills it and
	// removes its temporary directory.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	docs, err := eval.Evaluate(ctx, c.Args().First(), &eval.Options{
		Root:         root,
		Stacks:       c.StringSlice("stack"),
		Timeout:      c.Duration("timeout"),
		BuildTimeout: c.Duration("build-timeout"),
		MaxResources: c.Int("max-resources"),
		Python:       c.String("python"),
		Go:           c.String("go"),
		GoModCache:   c.String("gomodcache"),
		GoCache:      c.String("gocache"),
	})
	if err != nil {
		code := constants.EngineErrorCode
		if ctx.Err() != nil {
			code = constants.SignalInterruptCode
		}
		return errorWithExitCode(err, code)
	}

	var out io.Writer = os.Stdout
	if path := c.String("output"); path != "" {
		f, err := os.Create(path) //nolint:gosec // an output path given by the operator
		if err != nil {
			return errorWithExitCode(err, constants.EngineErrorCode)
		}
		defer func() { _ = f.Close() }()
		out = f
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(docs); err != nil {
		return errorWithExitCode(err, constants.EngineErrorCode)
	}
	failed := false
	log := logger.FromContext(ctx)
	for i := range docs {
		if r := docs[i].Result; r.Status != capture.StatusEvaluated {
			failed = true
			log.Warn().Str("stack", docs[i].Stack).Str("reason", string(r.Reason)).Str("message", r.Message).
				Msg("pulumi stack not evaluated")
		}
	}
	if failed {
		// The documents say why; stdout must stay valid JSON.
		return exitCode(pulumiEvalNotEvaluated)
	}
	return nil
}
