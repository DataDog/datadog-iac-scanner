package main

import (
	"context"

	"github.com/rs/zerolog/log"
	cli "github.com/urfave/cli/v3"
)

// Shared retired flags must be removed from both scan and serve in the same change.
func sharedRetiredFlags() []cli.Flag {
	return nil
}

func retiredScanOnlyFlags() []cli.Flag {
	return []cli.Flag{
		&cli.IntFlag{
			Name:   "timeout",
			Hidden: true,
			Action: retiredFlagAction[int]("timeout"),
		},
	}
}

func retiredServeOnlyFlags() []cli.Flag {
	return nil
}

func retiredScanFlags() []cli.Flag {
	return joinRetiredFlags(retiredScanOnlyFlags())
}

func retiredServeFlags() []cli.Flag {
	return joinRetiredFlags(retiredServeOnlyFlags())
}

func joinRetiredFlags(specific []cli.Flag) []cli.Flag {
	return append(append([]cli.Flag{}, sharedRetiredFlags()...), specific...)
}

func retiredFlagAction[T any](name string) func(context.Context, *cli.Command, T) error {
	return func(ctx context.Context, _ *cli.Command, _ T) error {
		log.Ctx(ctx).Warn().Str("flag", name).Msg("ignoring retired flag")
		return nil
	}
}
