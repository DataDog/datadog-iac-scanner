package main

import (
	"context"
	"fmt"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	cli "github.com/urfave/cli/v3"
)

var listQueriesAction = &cli.Command{
	Name:  "list-queries",
	Usage: "Returns a list of all available query ids",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "platform",
			Usage: "display the query's platform",
			Value: false,
		},
		&cli.BoolFlag{
			Name:  "name",
			Usage: "display the query's name",
			Value: false,
		},
	},
	Action: listQueries,
}

func listQueries(ctx context.Context, c *cli.Command) error {
	querySource := source.NewFilesystemSource(
		ctx,
		[]string{"./assets/queries"},
		GetSupportedPlatforms(),
		[]string{""},
		"./assets/libraries",
		false)

	queryFilter := source.QueryInspectorParameters{
		FlagEvaluator: featureflags.NewLocalEvaluator(),
	}

	queries, err := querySource.GetQueries(ctx, &queryFilter)
	if err != nil {
		return err
	}
	for _, query := range queries {
		fmt.Print(query.Metadata["id"])
		if c.Bool("platform") {
			fmt.Print(" ", query.Metadata["platform"])
		}
		if c.Bool("name") {
			fmt.Printf(" %q", query.Metadata["queryName"])
		}
		fmt.Println()
	}
	return nil
}
