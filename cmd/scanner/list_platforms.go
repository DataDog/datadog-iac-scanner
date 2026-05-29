package main

import (
	"context"
	"fmt"

	"github.com/DataDog/datadog-iac-scanner/internal/constants"
	cli "github.com/urfave/cli/v3"
)

var listPlatformsAction = &cli.Command{
	Name:   "list-platforms",
	Usage:  "Returns a list of all available platforms",
	Action: listPlatforms,
}

func listPlatforms(ctx context.Context, c *cli.Command) error {
	for _, platform := range constants.SupportedPlatforms {
		fmt.Println(platform)
	}
	return nil
}
