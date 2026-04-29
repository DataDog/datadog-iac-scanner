package main

import (
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/resolver/kustomize"
	cli "github.com/urfave/cli/v3"
)

// internalAction holds hidden subcommands the scanner re-execs (e.g. kustomize
// render in a child the parent can kill on timeout). Hidden from --help.
var internalAction = &cli.Command{
	Name:   "internal",
	Hidden: true,
	Usage:  "internal helpers used by the scanner to re-exec itself; not for direct use",
	Commands: []*cli.Command{
		{
			Name:   "kustomize-render",
			Hidden: true,
			Usage:  "run a single kustomize build; reads a JSON request from stdin and writes a JSON response to stdout",
			Action: func(ctx context.Context, c *cli.Command) error {
				return kustomize.RunHelperFromStdin()
			},
		},
	},
}
