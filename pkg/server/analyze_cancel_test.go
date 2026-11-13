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

func joinStrings(parts []string, sep string) string { return strings.Join(parts, sep) }


// A canceled or timed-out request stops the analyze scan promptly — expansion
// included — and the handler reports the failure instead of scanning the
// modules that were evaluated only in part.
func TestAnalyze_StopsWhenTheRequestContextIsDone(t *testing.T) {
	// The pushed-file scan expands dynamic blocks while converting each file;
	// a block whose for_each asks for far more blocks than any earlier limit
	// is the unbounded work a canceled request must stop.
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
			{Path: "infra/terraform.tfvars", Content: "ports = [" + joinStrings(rules, ", ") + "]"},
		},
		Platform: []string{"terraform"},
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.analyze(canceled, &req)
	require.ErrorIs(t, err, context.Canceled)

	deadline, dl := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer dl()
	start := time.Now()
	_, err = s.analyze(deadline, &req)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), 10*time.Second, "the analyze scan must stop promptly at the deadline")

	// The HTTP handler surfaces the failure as a 500 carrying the context
	// error, not as a response computed from partly evaluated modules.
	body, err := json.Marshal(req)
	require.NoError(t, err)
	httpReq := httptest.NewRequest(http.MethodPost, "/analyze", bytes.NewReader(body)).WithContext(deadline)
	rec := httptest.NewRecorder()
	s.handleAnalyze(rec, httpReq)
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Contains(t, rec.Body.String(), "context deadline exceeded")
}
