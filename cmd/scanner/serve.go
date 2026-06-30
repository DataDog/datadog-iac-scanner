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
		&cli.IntFlag{
			Name:  "max-files",
			Value: 50000,
			Usage: "maximum number of files accepted in a single /analyze request",
		},
		&cli.IntFlag{
			Name:  "max-request-mib",
			Value: 32,
			Usage: "maximum /analyze request body size in MiB (the JSON body, larger than raw file bytes)",
		},
		&cli.IntFlag{
			Name:  "write-timeout",
			Value: 600,
			Usage: "seconds allowed to write a response before the connection is closed " +
				"(0 disables; generous because a cold scan recompiles the rule corpus)",
		},
		&cli.BoolFlag{
			Name:   "x-use-rules-cache",
			Hidden: true,
			Value:  false,
			Usage: "(experimental, will be removed soon) cache compiled rules and co-compile them " +
				"into a shared compiler (rules cache + disabled rule isolation), for faster repeat " +
				"scans at low memory",
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

	// --write-timeout 0 means "disable"; Config treats a negative duration as
	// disabled (zero would be read as "apply default").
	writeTimeout := time.Duration(c.Int("write-timeout")) * time.Second
	if c.Int("write-timeout") == 0 {
		writeTimeout = -1
	}

	// --x-use-rules-cache is a single toggle for the rules-caching mode: it both
	// caches compiled rules across requests and co-compiles them into a shared
	// compiler. The two are deliberately not separately configurable.
	useRulesCache := c.Bool("x-use-rules-cache")

	cfg := server.Config{
		Address:              c.String("address"),
		Port:                 c.Int("port"),
		KeepAliveTimeout:     time.Duration(c.Int("keep-alive-timeout")) * time.Second,
		EnableShutdown:       c.Bool("enable-shutdown"),
		LibrariesPath:        c.String("libraries-path"),
		QueriesPath:          c.String("queries-path"),
		MaxConcurrentAnalyze: c.Int("max-concurrent-analyze"),
		MaxFiles:             c.Int("max-files"),
		MaxRequestBytes:      int64(c.Int("max-request-mib")) << 20,
		WriteTimeout:         writeTimeout,
		ParallelParsing:      c.Bool("x-parallelparsing"),
		UseRulesCache:        useRulesCache,
		DisableRuleIsolation: useRulesCache,
	}
	return server.New(&cfg).ListenAndServe(ctx)
}
