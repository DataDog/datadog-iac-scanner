package main

import (
	"context"
	"os/signal"
	"syscall"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/server"
	cli "github.com/urfave/cli/v3"
)

var serveAction = &cli.Command{
	Name:  "serve",
	Usage: "Runs a long-lived HTTP server that analyzes IaC files on demand",
	Flags: []cli.Flag{
		&cli.IntFlag{
			Name:  "port",
			Value: 8000,
			Usage: "port to listen on",
		},
		&cli.StringFlag{
			Name:  "address",
			Value: "127.0.0.1",
			Usage: "address to bind to",
		},
		&cli.IntFlag{
			Name:  "keep-alive-timeout",
			Value: 90,
			Usage: "seconds without a request before auto-shutdown (0 disables)",
		},
		&cli.BoolFlag{
			Name:  "enable-shutdown",
			Value: false,
			Usage: "allow POST/GET /shutdown to stop the server",
		},
		&cli.IntFlag{
			Name:  "max-concurrent-analyze",
			Value: 4,
			Usage: "maximum concurrent /analyze scans before returning 503 (must be > 0)",
		},
		&cli.BoolFlag{
			Name:   "x-use-rules-cache",
			Hidden: true,
			Usage: "(experimental, will be removed soon) cache compiled rules across requests so " +
				"warm scans skip recompilation (faster repeat scans at the cost of retained memory)",
			Value: false,
		},
		&cli.StringFlag{
			Name:  "libraries-path",
			Value: "./assets/libraries",
			Usage: "path to the Rego support libraries",
		},
		&cli.StringFlag{
			Name:  "queries-path",
			Value: "./assets/queries",
			Usage: "path to the default rule corpus (used only when a request omits its own rules)",
		},
		&cli.BoolFlag{
			Name:   "x-disable-rule-isolation",
			Hidden: true,
			Usage: "(experimental, will be removed soon) co-compile all rules and libraries into a " +
				"shared compiler instead of isolating each rule; greatly reduces memory at the cost " +
				"of per-rule compile-failure isolation",
			Value: false,
		},
		&cli.BoolFlag{
			Name:   "x-parallelparsing",
			Hidden: true,
			Usage:  "(experimental, will be removed soon) parse pushed files in parallel across CPUs",
			Value:  false,
		},
	},
	Action: serve,
}

func serve(ctx context.Context, c *cli.Command) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := server.Config{
		Address:              c.String("address"),
		Port:                 c.Int("port"),
		KeepAliveTimeout:     time.Duration(c.Int("keep-alive-timeout")) * time.Second,
		EnableShutdown:       c.Bool("enable-shutdown"),
		LibrariesPath:        c.String("libraries-path"),
		QueriesPath:          c.String("queries-path"),
		MaxConcurrentAnalyze: c.Int("max-concurrent-analyze"),
		DisableRuleIsolation: c.Bool("x-disable-rule-isolation"),
		ParallelParsing:      c.Bool("x-parallelparsing"),
		UseRulesCache:        c.Bool("x-use-rules-cache"),
	}
	return server.New(&cfg).ListenAndServe(ctx)
}
