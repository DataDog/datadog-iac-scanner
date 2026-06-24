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
		&cli.BoolFlag{
			Name:  "use-rules-cache",
			Value: false,
			Usage: "accepted for compatibility with the static-analyzer server contract; currently a no-op",
		},
		&cli.IntFlag{
			Name:  "rule-timeout-ms",
			Value: 0,
			Usage: "per-query evaluation timeout in milliseconds (0 uses the default of 60s)",
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
	},
	Action: serve,
}

const msPerSecond = 1000

func serve(ctx context.Context, c *cli.Command) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Mirror the static-analyzer server's --rule-timeout-ms flag onto the IaC
	// engine's per-query timeout (which is expressed in seconds).
	queryExecTimeout := 60
	if ms := c.Int("rule-timeout-ms"); ms > 0 {
		queryExecTimeout = max(ms/msPerSecond, 1)
	}

	cfg := server.Config{
		Address:          c.String("address"),
		Port:             c.Int("port"),
		KeepAliveTimeout: time.Duration(c.Int("keep-alive-timeout")) * time.Second,
		EnableShutdown:   c.Bool("enable-shutdown"),
		LibrariesPath:    c.String("libraries-path"),
		QueriesPath:      c.String("queries-path"),
		QueryExecTimeout: queryExecTimeout,
	}
	return server.New(&cfg).ListenAndServe(ctx)
}
