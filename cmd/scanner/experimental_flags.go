package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	cli "github.com/urfave/cli/v3"
)

const unknownFlagErrPrefix = "flag provided but not defined: "

// runCLI executes the root command, ignoring unknown hidden experimental flags
// (names starting with "x-") so callers can drop deprecated toggles without
// coordinated releases. Typos on real flags still fail fast.
func runCLI(ctx context.Context, cmd *cli.Command, args []string) error {
	for {
		err := cmd.Run(ctx, args)
		if err == nil {
			return nil
		}

		flagName, ok := unknownExperimentalFlagName(err)
		if !ok {
			return err
		}

		log.Warn().Str("flag", flagName).Msg("ignoring unknown experimental flag")
		args = removeFlagArg(args, flagName)
	}
}

func unknownExperimentalFlagName(err error) (string, bool) {
	msg := err.Error()
	if !strings.HasPrefix(msg, unknownFlagErrPrefix) {
		return "", false
	}

	flagName := strings.TrimPrefix(msg, unknownFlagErrPrefix)
	flagName = strings.TrimPrefix(flagName, "-")
	if !strings.HasPrefix(flagName, "x-") {
		return "", false
	}

	return flagName, true
}

func removeFlagArg(args []string, flagName string) []string {
	flagName = strings.TrimPrefix(flagName, "-")
	longForm := "--" + flagName
	shortForm := "-" + flagName

	filtered := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == longForm, arg == shortForm:
			if i+1 < len(args) && !looksLikeCLIArg(args[i+1]) {
				i++
			}
			continue
		case strings.HasPrefix(arg, longForm+"="), strings.HasPrefix(arg, shortForm+"="):
			continue
		default:
			filtered = append(filtered, arg)
		}
	}

	return filtered
}

func looksLikeCLIArg(arg string) bool {
	return strings.HasPrefix(arg, "-")
}

func applyUsageErrorHandlers(cmd *cli.Command) {
	cmd.OnUsageError = usageErrorHandler
	for _, sub := range cmd.Commands {
		applyUsageErrorHandlers(sub)
	}
}

func usageErrorHandler(ctx context.Context, cmd *cli.Command, err error, _ bool) error {
	if _, ok := unknownExperimentalFlagName(err); ok {
		return err
	}

	_, _ = fmt.Fprintf(cmd.Root().ErrWriter, "Incorrect Usage: %s\n\n", err.Error())
	if cmd == cmd.Root() {
		_ = cli.ShowRootCommandHelp(cmd)
	} else {
		_ = cli.ShowSubcommandHelp(cmd)
	}

	return err
}
