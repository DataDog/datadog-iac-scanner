/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A dynamic block whose for_each asks for far more blocks than any earlier
// limit is the unbounded conversion work a canceled request must stop. The
// request context expires while the handler is mid-scan, and the failure must
// surface as a 500 — a 200 here would be a response computed from partly
// converted files.
//
// The module expansion path is not reachable from this endpoint: pushed local
// module calls do not resolve against the in-memory filesystem, so that path
// is pinned at the tfeval and engine layers instead.
func TestAnalyze_HugeDynamicBlockStopsWhenTheRequestContextIsDone(t *testing.T) {
	var rules []string
	for range 300000 {
		rules = append(rules, "0")
	}
	s := newTestServer(t)
	req := analyzeRequest{
		Ruleset:   ruleset(syntheticRule()),
		Libraries: testLibraries(true),
		Files: []analyzeFile{
			{Path: "infra/main.tf", Content: `
variable "ports" { default = null }
resource "aws_security_group" "sg" {
  dynamic "ingress" {
    for_each = var.ports
    content {
      from_port = ingress.value
    }
  }
}
`},
			{Path: "infra/terraform.tfvars", Content: "ports = [" + strings.Join(rules, ", ") + "]"},
		},
		Platform: []string{"terraform"},
	}

	deadline, dl := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer dl()
	start := time.Now()
	_, err := s.analyze(deadline, &req)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), 10*time.Second, "the analyze scan must stop promptly at the deadline")

	body, err := json.Marshal(req)
	require.NoError(t, err)
	httpReq := httptest.NewRequest(http.MethodPost, "/analyze", bytes.NewReader(body)).WithContext(deadline)
	rec := httptest.NewRecorder()
	s.handleAnalyze(rec, httpReq)
	require.Equal(t, http.StatusInternalServerError, rec.Code, "body: %s", rec.Body.String())
	require.Contains(t, rec.Body.String(), "context")
}
