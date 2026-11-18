/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com/)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

func TestClassifyFailure(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"budget exceeded", &BudgetExceededError{Gate: "acquisition", Limit: "module_bytes_total"}, FailureBudgetExceeded},
		{"context deadline", context.DeadlineExceeded, FailureTimeout},
		{"context canceled", context.Canceled, FailureTimeout},
		{"host allowlist", fmt.Errorf("module host %q is not in --module-host-allowlist", "example.com"), FailureAllowlistDenied},
		{"http destination denied", fmt.Errorf("HTTP destination host %q is not in --module-host-allowlist", "example.com"), FailureAllowlistDenied},
		{"registry not found", fmt.Errorf("versions endpoint returned HTTP 404"), FailureNotFound},
		{"registry empty", fmt.Errorf("no versions published"), FailureNotFound},
		{"no parseable versions", fmt.Errorf("no parseable versions published"), FailureNotFound},
		{"http client error", fmt.Errorf("discovery returned HTTP 403"), FailureHTTPClient},
		{"http server error", fmt.Errorf("versions endpoint returned HTTP 502"), FailureHTTPServer},
		{"dns failure", fmt.Errorf("dial tcp: lookup registry.terraform.io: no such host"), FailureNetwork},
		{"destination dns failure is network, not allowlist", fmt.Errorf("resolving HTTP destination host %q: dial tcp: lookup example.com: no such host", "example.com"), FailureNetwork},
		{"joined dot-terraform miss and http 500 is http_5xx, not registry_not_found", fmt.Errorf("module \"network\" not found in .terraform/modules; versions endpoint returned HTTP 500"), FailureHTTPServer},
		{"connection refused", fmt.Errorf("connection refused"), FailureNetwork},
		{"unpack failure", fmt.Errorf("unpacking archive: gzip: invalid header"), FailureUnpack},
		{"unknown error", fmt.Errorf("something novel"), FailureUnknown},
		{"a code set by the error wins over its text", &tfmodules.UnresolvedError{Reason: "connection refused", Code: FailureGitRefNotFound}, FailureGitRefNotFound},
		{"detail is read by the text rules", &tfmodules.UnresolvedError{Reason: "fetch failed", Detail: "dial tcp: no such host"}, FailureNetwork},
		{"wrapped timeout", fmt.Errorf("fetching module: %w", context.DeadlineExceeded), FailureTimeout},
		{"wrapped budget", fmt.Errorf("module package rejected: %w", &BudgetExceededError{Gate: "acquisition"}), FailureBudgetExceeded},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, ClassifyFailure(tc.err))
		})
	}
}
