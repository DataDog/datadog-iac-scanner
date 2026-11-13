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

	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/stretchr/testify/require"
)

// bucketOwnerRule is the synthetic rule shaped so its Terraform resource types
// are readable by name (a literal type in the Rego), which is what lets module
// evaluation run for the request's pushed modules.
func bucketOwnerRule() datadog.Rule {
	r := syntheticRule()
	r.RegoQuery = []byte(`package datadog

import rego.v1

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

DatadogPolicy contains result if {
	common_lib.library_enabled
	some i, name
	resource := input.document[i].resource.aws_s3_bucket[name]
	not common_lib.has_owner(resource)
	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": tf_lib.display_name("aws_s3_bucket", name),
		"searchKey": sprintf("aws_s3_bucket[%s].labels.owner", [name]),
	}
}`)
	return r
}

// postAnalyzeContext runs the handler with the given request context and
// asserts the failure shape: a canceled or timed-out scan must come back as a
// 500 carrying the context error, never as a response computed from partly
// evaluated modules.
func postAnalyzeContext(t *testing.T, s *Server, req analyzeRequest, reqCtx context.Context) {
	t.Helper()
	body, err := json.Marshal(req)
	require.NoError(t, err)
	httpReq := httptest.NewRequest(http.MethodPost, "/analyze", bytes.NewReader(body)).WithContext(reqCtx)
	rec := httptest.NewRecorder()
	s.handleAnalyze(rec, httpReq)
	require.Equal(t, http.StatusInternalServerError, rec.Code, "body: %s", rec.Body.String())
	require.Contains(t, rec.Body.String(), "context")
}

// Local modules expand through this endpoint: one sane call and one whose
// count cannot be enumerated. The request context expires while the handler is
// still expanding the huge call — it cannot finish — so a 200 here would mean
// the module findings were silently lost. The failure must surface as a 500.
func TestAnalyze_HugeCountModuleStopsWhenTheRequestContextIsDone(t *testing.T) {
	s := newTestServer(t)
	req := analyzeRequest{
		Ruleset:   ruleset(bucketOwnerRule()),
		Libraries: testLibraries(true),
		Files: []analyzeFile{
			{Path: "infra/instances/main.tf", Content: `
variable "in" { type = string }
resource "aws_s3_bucket" "b" { bucket = var.in }
`},
			{Path: "infra/tfeval/main.tf", Content: `
module "sane" {
  source = "../instances"
  count  = 2
  in     = "sane-${count.index}"
}
module "huge" {
  source = "../instances"
  count  = 9223372036854775807
  in     = "huge-${count.index}"
}
`},
		},
		Platform: []string{"terraform"},
	}

	// The same shape without the huge call expands: every sane instance gets
	// its own finding attributed to its module address.
	sane := analyzeRequest{
		Ruleset:   ruleset(bucketOwnerRule()),
		Libraries: testLibraries(true),
		Files: []analyzeFile{
			req.Files[0],
			{Path: "infra/tfeval/main.tf", Content: `
module "sane" {
  source = "../instances"
  count  = 2
  in     = "sane-${count.index}"
}
`},
		},
		Platform: []string{"terraform"},
	}
	out, err := s.analyze(context.Background(), &sane)
	require.NoError(t, err)
	require.Len(t, out.Findings, 2)
	chains := map[string]bool{}
	for _, f := range out.Findings {
		chains[f.ModuleCallChain] = true
	}
	require.Len(t, chains, 2, "each module instance is attributed to its own address")

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.analyze(canceled, &req)
	require.ErrorIs(t, err, context.Canceled)

	deadline, dl := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer dl()
	start := time.Now()
	_, err = s.analyze(deadline, &req)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), 10*time.Second, "the analyze scan must stop promptly at the deadline")

	postAnalyzeContext(t, s, req, deadline)
}

// A dynamic block whose for_each asks for far more blocks than any earlier
// limit is unbounded conversion work; a request whose deadline expires during
// it fails with the context error rather than answering from partly converted
// files.
func TestAnalyze_HugeDynamicBlockStopsWhenTheRequestContextIsDone(t *testing.T) {
	var rules []string
	for range 300000 {
		rules = append(rules, "0")
	}
	s := newTestServer(t)
	req := analyzeRequest{
		Ruleset:   ruleset(bucketOwnerRule()),
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

	postAnalyzeContext(t, s, req, deadline)
}
