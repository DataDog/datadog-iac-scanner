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
	// shutdownGraceTimeout matches the static-analyzer server: its keep-alive
	// loop notifies a graceful shutdown, then allows 10s before escalating to
	// process abort. We give in-flight requests the same window via http.Server.Shutdown.
	shutdownGraceTimeout = 10 * time.Second
	// keepAlivePollInterval matches the static-analyzer server's idle-check
	// cadence: it polls for inactivity every 5s.
	keepAlivePollInterval = 5 * time.Second
	// maxRequestBytes caps a single request body (applied by body-reading
	// handlers via http.MaxBytesReader). 32 MiB comfortably fits a directory of
	// IaC files plus the pushed rule corpus.
	maxRequestBytes = 32 << 20
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
}

// Server is the IaC analysis HTTP server.
type Server struct {
	cfg  Config
	http *http.Server

	// lastRequestNanos is the UnixNano timestamp of the most recent request,
	// updated by middleware and read by the keep-alive monitor.
	lastRequestNanos atomic.Int64

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
	s := &Server{cfg: *cfg, shutdownCh: make(chan struct{})}

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
		// No WriteTimeout: a cold scan recompiles the rule corpus and can take
		// several seconds until the prepared-query cache lands.
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
	ticker := time.NewTicker(keepAlivePollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.shutdownCh:
			return
		case <-ticker.C:
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
