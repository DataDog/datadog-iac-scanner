package main

import (
	"context"

	"github.com/rs/zerolog/log"
	cli "github.com/urfave/cli/v3"
)

const retiredTimeoutUsage = "(DEPRECATED) no longer has any effect; " +
	"queries run to completion and slow rules are logged instead. " +
	"This flag will be removed."

// Shared retired flags must be removed from both scan and serve in the same change.
func sharedRetiredFlags() []cli.Flag {
	return nil
}

func retiredScanOnlyFlags() []cli.Flag {
	return []cli.Flag{
		retiredInt("timeout", retiredTimeoutUsage),
	}
}

func retiredInt(name, usage string) *cli.IntFlag {
	return &cli.IntFlag{
		Name:   name,
		Hidden: true,
		Usage:  usage,
		Action: retiredFlagAction[int](name),
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
