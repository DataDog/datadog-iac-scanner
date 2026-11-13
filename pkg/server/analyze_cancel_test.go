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

// A request whose scan cannot finish inside its deadline must fail with the
// context error — the denial-of-service path for pushed content. Each row is
// an expansion that outlasts any deadline: a module call whose count cannot be
// enumerated, and a dynamic block asking for far more blocks than any earlier
// limit. The deadline expires while the handler is in flight, and the 500
// arrives after roughly the deadline, not before the handler started.
func TestAnalyze_StopsWhenTheRequestContextIsDone(t *testing.T) {
	moduleFiles := []analyzeFile{
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
	}
	saneFiles := []analyzeFile{
		moduleFiles[0],
		{Path: "infra/tfeval/main.tf", Content: `
module "sane" {
  source = "../instances"
  count  = 2
  in     = "sane-${count.index}"
}
`},
	}
	var rules []string
	for range 300000 {
		rules = append(rules, "0")
	}
	dynamicFiles := []analyzeFile{
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
	}

	rows := map[string]struct {
		req analyzeRequest
	}{
		"huge module count": {req: analyzeRequest{
			Ruleset:   ruleset(bucketOwnerRule()),
			Libraries: testLibraries(true),
			Files:     moduleFiles,
			Platform:  []string{"terraform"},
		}},
		"huge dynamic block": {req: analyzeRequest{
			Ruleset:   ruleset(bucketOwnerRule()),
			Libraries: testLibraries(true),
			Files:     dynamicFiles,
			Platform:  []string{"terraform"},
		}},
	}

	s := newTestServer(t)

	// Local modules expand through this endpoint: every instance of the sane
	// shape gets its own finding attributed to its module address.
	out, err := s.analyze(context.Background(), &analyzeRequest{
		Ruleset:   ruleset(bucketOwnerRule()),
		Libraries: testLibraries(true),
		Files:     saneFiles,
		Platform:  []string{"terraform"},
	})
	require.NoError(t, err)
	require.Len(t, out.Findings, 2)
	chains := map[string]bool{}
	for _, f := range out.Findings {
		chains[f.ModuleCallChain] = true
	}
	require.Len(t, chains, 2, "each module instance is attributed to its own address")

	for name, row := range rows {
		t.Run(name, func(t *testing.T) {
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			_, err := s.analyze(canceled, &row.req)
			require.ErrorIs(t, err, context.Canceled)

			deadlineCtx, dl := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer dl()
			body, err := json.Marshal(row.req)
			require.NoError(t, err)
			httpReq := httptest.NewRequest(http.MethodPost, "/analyze", bytes.NewReader(body)).WithContext(deadlineCtx)
			rec := httptest.NewRecorder()
			start := time.Now()
			done := make(chan int)
			go func() {
				s.handleAnalyze(rec, httpReq)
				done <- rec.Code
			}()
			select {
			case code := <-done:
				require.Equal(t, http.StatusInternalServerError, code, "body: %s", rec.Body.String())
				require.Contains(t, rec.Body.String(), "context deadline exceeded")
				require.GreaterOrEqual(t, time.Since(start), 400*time.Millisecond,
					"the handler must still be working when the deadline lands, not start after it")
			case <-time.After(60 * time.Second):
				t.Fatal("the handler did not return after the request context expired")
			}
		})
	}
}
