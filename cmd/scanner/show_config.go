package main

import (
	"context"
	"fmt"

	"github.com/DataDog/datadog-iac-scanner/pkg/config"
	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	cli "github.com/urfave/cli/v3"
)

var showConfigAction = &cli.Command{
	Name:  "show-config",
	Usage: "Displays the Datadog IaC scanner configuration for this repository",
	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:        "path",
			Aliases:     []string{"p"},
			Usage:       "repository root path",
			DefaultText: ".",
		},
		&cli.BoolFlag{
			Name:  "local",
			Usage: "read only the local configuration",
			Value: false,
		},
	},
	Action: showConfig,
}

func showConfig(ctx context.Context, c *cli.Command) error {
	paths := c.StringSlice("path")
	if len(paths) == 0 {
		paths = []string{"."}
	}
	repoInfo, repoDir, err := getRepositoryCommitInfo(paths)
	if err != nil {
		return fmt.Errorf("error retrieving repository commit information: %w", err)
	}

	var cfgOptions []config.ReadConfigurationOption
	if !c.Bool("local") {
		cfgOptions = append(cfgOptions, config.WithDatadog(datadog.NewDatadogClient(), repoInfo.RepositoryUrl))
	}

	parsed, cfgFile, err := config.ReadConfiguration(ctx, repoDir, cfgOptions...)
	if err != nil {
		return fmt.Errorf("error reading the configuration: %w", err)
	}

	fmt.Println("Read configuration:")
	if len(cfgFile) == 0 {
		fmt.Println("<default configuration>")
		fmt.Println()
	} else {
		fmt.Println(string(cfgFile))
	}

	fmt.Println("Parsed configuration:")
	if parsed == nil {
		fmt.Println("<default configuration>")
	} else {
		fmt.Printf("%+v\n", *parsed)
	}

	return nil
}
