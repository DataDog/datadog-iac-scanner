package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	cli "github.com/urfave/cli/v3"
)

const defaultFailCode = 126

func main() {
	cmd := &cli.Command{
		Name:  "datadog-iac-scanner",
		Usage: "Scans your Infrastructure as Code configurations",
		Commands: []*cli.Command{
			scanAction,
			listPlatformsAction,
			listQueriesAction,
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
		},
		Before: applyGlobalOptions,
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		var exitCode *normalExitCode
		if errors.As(err, &exitCode) {
			os.Exit(exitCode.code)
		}

		fmt.Printf("Program failed: %v\n", err)
		os.Exit(defaultFailCode)
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
	return log.Logger.WithContext(ctx), nil
}

func exitCode(code int) error {
	return &normalExitCode{
		code: code,
	}
}

type normalExitCode struct {
	code int
}

func (e *normalExitCode) Error() string {
	return fmt.Sprintf("exit code %d", e.code)
}

func GetSupportedPlatforms() []string {
	return []string{"CICD", "Terraform", "Kubernetes", "CloudFormation"}
}
