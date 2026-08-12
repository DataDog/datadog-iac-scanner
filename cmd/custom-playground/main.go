// Command custom-playground serves a small local web UI for exercising custom Rego
// validate/evaluate — the same logic the IaC rule editor uses via the backend.
//
// Usage:
//
//	export DD_API_KEY=... DD_APP_KEY=...
//	go run ./cmd/custom-playground
//	open http://localhost:8765
package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	iacplatforms "github.com/DataDog/datadog-iac-scanner/pkg/platforms"
	"github.com/DataDog/datadog-iac-scanner/pkg/scan"
)

//go:embed static/*
var staticFS embed.FS

type validateRequest struct {
	Platform  string `json:"platform"`
	RegoQuery string `json:"regoQuery"`
}

type validateResponse struct {
	Errors []scan.RegoValidationError `json:"errors"`
}

type evaluateRequest struct {
	Platform   string `json:"platform"`
	RegoQuery  string `json:"regoQuery"`
	SampleFile string `json:"sampleFile"`
}

type evaluateFinding struct {
	Resource     string `json:"resource"`
	StartLine    int    `json:"start_line"`
	EndLine      int    `json:"end_line"`
	ResourceType string `json:"resource_type"`
	ResourceName string `json:"resource_name"`
	Message      string `json:"message"`
}

type evaluateResponse struct {
	Findings []evaluateFinding          `json:"findings"`
	Errors   []scan.RegoValidationError `json:"errors"`
}

const (
	defaultPort        = 8765
	validateTimeout    = 30 * time.Second
	evaluateTimeout    = 60 * time.Second
	serverReadTimeout  = 15 * time.Second
	serverWriteTimeout = 90 * time.Second
	serverIdleTimeout  = 120 * time.Second
)

func main() {
	port := flag.Int("port", defaultPort, "HTTP port")
	flag.Parse()

	libSource, err := source.NewDatadogSource(datadog.NewDatadogClient())
	if err != nil {
		log.Fatalf("library source: %v", err)
	}

	srv := &server{libSource: libSource}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/platforms", srv.handlePlatforms)
	mux.HandleFunc("POST /api/validate", srv.handleValidate)
	mux.HandleFunc("POST /api/evaluate", srv.handleEvaluate)

	static, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("static fs: %v", err)
	}
	mux.Handle("GET /", http.FileServer(http.FS(static)))

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("custom rule playground at http://localhost%s", addr)
	log.Printf("set DD_API_KEY and DD_APP_KEY to load Rego libraries from Datadog")
	httpServer := &http.Server{
		Addr:         addr,
		Handler:      withCORS(mux),
		ReadTimeout:  serverReadTimeout,
		WriteTimeout: serverWriteTimeout,
		IdleTimeout:  serverIdleTimeout,
	}
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

type server struct {
	libSource source.QueriesSource
}

func (s *server) handlePlatforms(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, iacplatforms.Supported)
}

func (s *server) handleValidate(w http.ResponseWriter, r *http.Request) {
	var req validateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := validatePlatform(req.Platform); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.RegoQuery) == "" {
		writeJSON(w, http.StatusOK, validateResponse{Errors: []scan.RegoValidationError{}})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), validateTimeout)
	defer cancel()

	errs, err := scan.ValidateCustomRegoQuery(ctx, req.Platform, req.RegoQuery, s.libSource)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if errs == nil {
		errs = []scan.RegoValidationError{}
	}
	writeJSON(w, http.StatusOK, validateResponse{Errors: errs})
}

func (s *server) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	var req evaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := validatePlatform(req.Platform); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), evaluateTimeout)
	defer cancel()

	errs, err := scan.ValidateCustomRegoQuery(ctx, req.Platform, req.RegoQuery, s.libSource)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(errs) > 0 {
		writeJSON(w, http.StatusOK, evaluateResponse{Findings: []evaluateFinding{}, Errors: errs})
		return
	}

	vulns, failedQueries, err := scan.RunCustomRegoQuery(ctx, req.Platform, req.RegoQuery, []byte(req.SampleFile))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	findings := make([]evaluateFinding, 0, len(vulns))
	for i := range vulns {
		v := &vulns[i]
		startLine := v.VulnerabilityLocation.Start.Line
		endLine := v.VulnerabilityLocation.End.Line
		if startLine == 0 {
			startLine = v.Line
			endLine = v.Line
		}
		findings = append(findings, evaluateFinding{
			Resource:     v.SearchKey,
			StartLine:    startLine,
			EndLine:      endLine,
			ResourceType: v.ResourceType,
			ResourceName: v.ResourceName,
			Message:      v.SearchKey,
		})
	}

	runtimeErrs := make([]scan.RegoValidationError, 0, len(failedQueries))
	for _, queryErr := range failedQueries {
		runtimeErrs = append(runtimeErrs, scan.RegoValidationError{
			Code:    "rego_runtime_error",
			Message: queryErr.Error(),
		})
	}

	writeJSON(w, http.StatusOK, evaluateResponse{Findings: findings, Errors: runtimeErrs})
}

func validatePlatform(platform string) error {
	for _, p := range iacplatforms.Supported {
		if strings.EqualFold(p, platform) {
			return nil
		}
	}
	return fmt.Errorf("unsupported platform %q, must be one of %v", platform, iacplatforms.Supported)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		log.Printf("encode response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
