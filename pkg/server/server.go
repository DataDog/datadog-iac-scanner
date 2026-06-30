/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package server implements a long-lived HTTP server that analyzes IaC files on
// demand. It mirrors the contract of the Rust datadog-static-analyzer-server so
// the Datadog VS Code extension can manage both binaries through the same
// lifecycle (keep-alive ping, graceful shutdown, version discovery).
//
// The server is a pure engine: it never reads git, calls the Datadog API, or
// writes SARIF. Rules and file content are pushed over HTTP by the extension.
//
// Lifecycle endpoints (this file):
//
//	GET  /ping      health / keep-alive (resets the idle timer), returns "pong"
//	GET  /version   running binary version (plain text)
//	GET  /revision  running binary commit (plain text)
//	POST /shutdown  graceful shutdown (204 when --enable-shutdown, else 403)
//	GET  /shutdown  same as POST
//
// IaC endpoints (GET /ide/v1/iac/supported-files, POST /ide/v1/iac/analyze) are
// registered here and implemented in sibling files.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DataDog/datadog-iac-scanner/internal/constants"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/rs/zerolog/log"
)

const (
	// readHeaderTimeout / readTimeout are explicit slowloris guards
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 60 * time.Second
	// idleTimeout bounds how long an idle keep-alive TCP connection is held open
	// between requests, so abandoned connections don't accumulate.
	idleTimeout = 120 * time.Second
	// shutdownGraceTimeout matches the static-analyzer server: its keep-alive
	// loop notifies a graceful shutdown, then allows 10s before escalating to
	// process abort. We give in-flight requests the same window via http.Server.Shutdown.
	shutdownGraceTimeout = 10 * time.Second
	// keepAlivePollInterval matches the static-analyzer server's idle-check
	// cadence: it polls for inactivity every 5s.
	keepAlivePollInterval = 5 * time.Second
	// defaultMaxRequestBytes caps a single request body (applied by body-reading
	// handlers via http.MaxBytesReader). 32 MiB comfortably fits most directories
	// of IaC files plus the pushed rule corpus; raise it via Config.MaxRequestBytes
	// for very large monorepos. Note the cap is on the JSON-encoded body, which is
	// larger than the raw file bytes (escaping).
	defaultMaxRequestBytes = 32 << 20
	// defaultMaxConcurrentAnalyze bounds how many /analyze scans run at once.
	// Each scan buffers up to maxRequestBytes and spins worker goroutines, so an
	// unbounded burst could exhaust memory/goroutines.
	defaultMaxConcurrentAnalyze = 4
	// defaultWriteTimeout bounds how long a response write may take, so a client
	// that stops reading cannot pin a handler goroutine indefinitely. It is
	// generous because a cold scan recompiles the whole rule corpus (seconds) and
	// can be larger still on huge repos; tune via Config.WriteTimeout. 0 disables.
	defaultWriteTimeout = 10 * time.Minute
	// defaultMaxFiles bounds the number of files in a single /analyze request.
	defaultMaxFiles = 50000
	// defaultMaxRules bounds the number of rules in a single /analyze request.
	defaultMaxRules = 10000
)

// Config holds the server's runtime settings, populated from the serve command's
// flags.
type Config struct {
	Address          string        // bind address (default 127.0.0.1)
	Port             int           // listen port (default 8000)
	KeepAliveTimeout time.Duration // idle timeout; 0 disables auto-shutdown
	EnableShutdown   bool          // gate for the /shutdown endpoint
	LibrariesPath    string        // Rego support libraries
	QueriesPath      string        // default rule corpus (used only when a request omits rules)
	// MaxConcurrentAnalyze caps simultaneous /analyze scans. <= 0 applies
	// defaultMaxConcurrentAnalyze.
	MaxConcurrentAnalyze int
	// DisableRuleIsolation opts into the engine's shared-compiler mode (rules +
	// libraries co-compiled once) instead of isolating each rule. Lowers memory
	// substantially at the cost of per-rule compile-failure isolation.
	DisableRuleIsolation bool
	// UseRulesCache enables the process-global compiled-query cache so repeated
	// /analyze scans reuse compiled rules (warm scans skip recompilation, at the
	// cost of retained memory). Maps to the --use-rules-cache server flag.
	UseRulesCache bool
	// ParallelParsing fans the per-file parse across CPUs for pushed content.
	// Measured ~26% faster wall-clock on a 950-file push; same CPU total. Maps
	// to the experimental --x-parallelparsing server flag.
	ParallelParsing bool
	// WriteTimeout bounds how long writing a response may take, so a client that
	// stops reading cannot hold a handler goroutine indefinitely. Zero applies
	// defaultWriteTimeout; a NEGATIVE value disables the timeout entirely (mapped
	// to http.Server.WriteTimeout = 0). Maps to the --write-timeout server flag.
	WriteTimeout time.Duration
	// MaxFiles caps the number of files in a single /analyze request. <= 0
	// applies defaultMaxFiles. Maps to the --max-files server flag.
	MaxFiles int
	// MaxRequestBytes caps the JSON-encoded /analyze request body. <= 0 applies
	// defaultMaxRequestBytes. Maps to the --max-request-mib server flag.
	MaxRequestBytes int64
}

// Server is the IaC analysis HTTP server.
type Server struct {
	cfg  Config
	http *http.Server

	// lastRequestNanos is the UnixNano timestamp of the most recent request
	// boundary (start and completion), updated by middleware and read by the
	// keep-alive monitor.
	lastRequestNanos atomic.Int64

	// inFlight counts requests currently being handled. The keep-alive monitor
	// never shuts down while this is non-zero, so a long scan with no concurrent
	// /ping is not mistaken for an idle server and killed mid-flight.
	inFlight atomic.Int64

	// analyzeSem bounds concurrent /analyze scans (acquire-or-503). Buffered to
	// cfg.MaxConcurrentAnalyze.
	analyzeSem chan struct{}

	// pollInterval is the keep-alive monitor's check cadence; defaults to
	// keepAlivePollInterval and is overridable in tests.
	pollInterval time.Duration

	// shutdownCh is closed exactly once to trigger graceful shutdown (by
	// /shutdown, the keep-alive monitor, or a canceled context).
	shutdownCh   chan struct{}
	shutdownOnce sync.Once
}

// New builds a server from cfg, applying defaults for any zero-valued field.
func New(cfg *Config) *Server {
	if cfg.Address == "" {
		cfg.Address = "127.0.0.1"
	}
	if cfg.Port == 0 {
		cfg.Port = 8000
	}
	if cfg.LibrariesPath == "" {
		cfg.LibrariesPath = "./assets/libraries"
	}
	if cfg.QueriesPath == "" {
		cfg.QueriesPath = "./assets/queries"
	}
	if cfg.MaxConcurrentAnalyze <= 0 {
		cfg.MaxConcurrentAnalyze = defaultMaxConcurrentAnalyze
	}
	switch {
	case cfg.WriteTimeout == 0:
		cfg.WriteTimeout = defaultWriteTimeout
	case cfg.WriteTimeout < 0:
		cfg.WriteTimeout = 0 // explicitly disabled
	}
	if cfg.MaxFiles <= 0 {
		cfg.MaxFiles = defaultMaxFiles
	}
	if cfg.MaxRequestBytes <= 0 {
		cfg.MaxRequestBytes = defaultMaxRequestBytes
	}
	s := &Server{
		cfg:          *cfg,
		analyzeSem:   make(chan struct{}, cfg.MaxConcurrentAnalyze),
		pollInterval: keepAlivePollInterval,
		shutdownCh:   make(chan struct{}),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /ping", s.handlePing)
	mux.HandleFunc("GET /version", s.handleVersion)
	mux.HandleFunc("GET /revision", s.handleRevision)
	mux.HandleFunc("POST /shutdown", s.handleShutdown)
	mux.HandleFunc("GET /shutdown", s.handleShutdown)
	// CORS preflight: a path-wildcard pattern scoped to OPTIONS so it never
	// shadows the method-specific routes above.
	mux.HandleFunc("OPTIONS /", s.handleOptions)
	// IaC endpoints (implemented in sibling files):
	mux.HandleFunc("GET /ide/v1/iac/supported-files", s.handleSupportedFiles)
	mux.HandleFunc("POST /ide/v1/iac/analyze", s.handleAnalyze)

	s.http = &http.Server{
		Addr:              net.JoinHostPort(cfg.Address, strconv.Itoa(cfg.Port)),
		Handler:           s.middleware(mux),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		IdleTimeout:       idleTimeout,
		WriteTimeout:      cfg.WriteTimeout,
	}
	return s
}

// ListenAndServe starts the server and blocks until it is shut down (via
// /shutdown, a canceled ctx, or the keep-alive timeout). A clean shutdown
// returns nil.
func (s *Server) ListenAndServe(ctx context.Context) error {
	contextLogger := logger.FromContext(ctx)
	s.lastRequestNanos.Store(time.Now().UnixNano())

	go func() {
		select {
		case <-ctx.Done():
		case <-s.shutdownCh:
		}
		s.gracefulShutdown()
	}()

	if s.cfg.KeepAliveTimeout > 0 {
		go s.keepAliveMonitor(ctx)
	}

	contextLogger.Info().Msgf("IaC analysis server listening on %s", s.http.Addr)
	if err := s.http.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// keepAliveMonitor shuts the server down after KeepAliveTimeout elapses with no
// requests, mirroring the SAST server's idle-exit behavior.
func (s *Server) keepAliveMonitor(ctx context.Context) {
	contextLogger := logger.FromContext(ctx)
	interval := s.pollInterval
	if interval <= 0 {
		interval = keepAlivePollInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.shutdownCh:
			return
		case <-ticker.C:
			// A request in flight means the server is busy, not idle — never
			// shut down underneath an active scan.
			if s.inFlight.Load() > 0 {
				continue
			}
			last := time.Unix(0, s.lastRequestNanos.Load())
			if time.Since(last) > s.cfg.KeepAliveTimeout {
				contextLogger.Info().Msg("keep-alive timeout reached; shutting down")
				s.triggerShutdown()
				return
			}
		}
	}
}

func (s *Server) triggerShutdown() {
	s.shutdownOnce.Do(func() { close(s.shutdownCh) })
}

func (s *Server) gracefulShutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGraceTimeout)
	defer cancel()
	_ = s.http.Shutdown(ctx)
}

// --- lifecycle handlers ---

func (s *Server) handlePing(w http.ResponseWriter, _ *http.Request) {
	writeText(w, http.StatusOK, "pong")
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeText(w, http.StatusOK, constants.Version)
}

func (s *Server) handleRevision(w http.ResponseWriter, _ *http.Request) {
	writeText(w, http.StatusOK, constants.SCMCommit)
}

func (s *Server) handleShutdown(w http.ResponseWriter, _ *http.Request) {
	if !s.cfg.EnableShutdown {
		writeError(w, http.StatusForbidden, "shutdown is disabled")
		return
	}
	// Flush the response before tearing the listener down; the actual shutdown
	// runs off the request goroutine so Shutdown does not wait on this handler.
	w.WriteHeader(http.StatusNoContent)
	s.triggerShutdown()
}

func (s *Server) handleOptions(w http.ResponseWriter, _ *http.Request) {
	// CORS headers are already set by middleware; just acknowledge the preflight.
	w.WriteHeader(http.StatusNoContent)
}

// --- middleware ---

// middleware updates the keep-alive timestamp, sets the standard response and
// CORS headers, attaches the global logger to the request context (so the scan
// pipeline's logger.FromContext works), and recovers from handler panics.
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.lastRequestNanos.Store(time.Now().UnixNano())
		s.inFlight.Add(1)
		defer func() {
			s.inFlight.Add(-1)
			// Restamp on completion so the idle window starts when the request
			// finishes, not when it began.
			s.lastRequestNanos.Store(time.Now().UnixNano())
		}()

		h := w.Header()
		h.Set("X-iac-scanner-server-version", constants.Version)
		h.Set("X-iac-scanner-server-revision", constants.SCMCommit)
		h.Set("X-iac-scanner-server-shutdown-enabled", strconv.FormatBool(s.cfg.EnableShutdown))
		h.Set("X-iac-scanner-server-keepalive-enabled", strconv.FormatBool(s.cfg.KeepAliveTimeout > 0))
		reqID := r.Header.Get("X-Request-Id")
		if reqID == "" {
			reqID = newRequestID()
		}
		h.Set("X-Request-Id", reqID)

		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Methods", "POST, GET, PATCH, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "*")
		h.Set("Access-Control-Allow-Credentials", "true")

		ctx := log.Logger.WithContext(r.Context())
		contextLogger := logger.FromContext(ctx)

		defer func() {
			if rec := recover(); rec != nil {
				contextLogger.Error().Msgf("panic serving %s %s: %v", r.Method, r.URL.Path, rec)
				// Best-effort; if the handler already wrote a status this is a no-op.
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// --- helpers ---

func writeText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b[:])
}
