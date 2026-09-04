package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/DataDog/datadog-iac-scanner/internal/constants"
	"github.com/DataDog/datadog-iac-scanner/internal/metrics"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	cli "github.com/urfave/cli/v3"
)

const defaultFailCode = 126

// gcPercent sets the garbage collection target percentage. A lower value makes
// the GC run more frequently, reclaiming transient allocations from OPA query
// evaluation faster and reducing peak memory usage.
const gcPercent = 50

func main() {
	if _, ok := os.LookupEnv("GOGC"); !ok {
		debug.SetGCPercent(gcPercent)
	}
	cmd := &cli.Command{
		Name:    "datadog-iac-scanner",
		Usage:   "Scans your Infrastructure as Code configurations",
		Version: constants.GetVersion(),
		Commands: []*cli.Command{
			scanAction,
			customAction,
			listPlatformsAction,
			listQueriesAction,
			listModulesAction,
			showConfigAction,
			testRulesAction,
			serveAction,
			fetchBundleAction,
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "log-format",
				Usage: "log format (pretty, json)",
				Value: "pretty",
			},
			&cli.StringFlag{
				Name:  "log-level",
				Usage: "minimum log level to display (trace, debug, info, warn, error, fatal, panic, disable)",
				Value: "error",
			},
			&cli.StringFlag{
				Name:  "profiling",
				Usage: "enables profiling; one of CPU or MEM (results logged at info level)",
			},
		},
		Before: applyGlobalOptions,
	}
	applyUsageErrorHandlers(cmd)

	if err := runCLI(context.Background(), cmd, os.Args); err != nil {
		code := defaultFailCode
		if exitCode := (*withExitCodeError)(nil); errors.As(err, &exitCode) {
			code = exitCode.code
			err = exitCode.err
		}
		if err != nil {
			fmt.Printf("Program failed: %v\n", err)
		}
		os.Exit(code)
	}
}

func applyGlobalOptions(ctx context.Context, c *cli.Command) (context.Context, error) {
	if c.String("log-format") == "pretty" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})
	}
	level, err := zerolog.ParseLevel(strings.ToLower(c.String("log-level")))
	if err != nil {
		return nil, fmt.Errorf("error parsing the log level: %w", err)
	}
	zerolog.SetGlobalLevel(level)
	if err := metrics.InitializeMetrics(c.String("profiling")); err != nil {
		return nil, err
	}
	return log.Logger.WithContext(ctx), nil
}

func exitCode(code int) error {
	return &withExitCodeError{
		code: code,
		err:  nil,
	}
}

func errorWithExitCode(err error, code int) error {
	return &withExitCodeError{
		code: code,
		err:  err,
	}
}

type withExitCodeError struct {
	code int
	err  error
}

func (e *withExitCodeError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return fmt.Sprintf("exit code %d", e.code)
}
