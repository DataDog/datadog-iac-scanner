/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com/)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/stretchr/testify/require"
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
		{"host allowlist", fmt.Errorf("module host %q is not in --module-host-allowlist", "example.com"), FailureHostNotAllowlisted},
		{"http destination denied", fmt.Errorf("HTTP destination host %q is not in --module-host-allowlist", "example.com"), FailureHostNotAllowlisted},
		{"registry module not found", fmt.Errorf("versions endpoint returned HTTP 404"), FailureRegistryModuleNotFound},
		{"registry empty", fmt.Errorf("no versions published"), FailureRegistryVersionNotFound},
		{"no parseable versions", fmt.Errorf("no parseable versions published"), FailureRegistryVersionNotFound},
		{"legacy 404 without endpoint", fmt.Errorf("request returned HTTP 404"), FailureNotFound},
		{"http client error", fmt.Errorf("discovery returned HTTP 403"), FailureHTTPClient},
		{"http server error", fmt.Errorf("versions endpoint returned HTTP 502"), FailureHTTPServer},
		{"dns failure", fmt.Errorf("dial tcp: lookup registry.terraform.io: no such host"), FailureNetwork},
		{"destination dns failure is network, not allowlist", fmt.Errorf("resolving HTTP destination host %q: dial tcp: lookup example.com: no such host", "example.com"), FailureNetwork},
		{"joined dot-terraform miss and http 500 is http_5xx, not registry_not_found", fmt.Errorf("module \"network\" not found in .terraform/modules; versions endpoint returned HTTP 500"), FailureHTTPServer},
		{"connection refused", fmt.Errorf("connection refused"), FailureNetwork},
		{"unpack failure", fmt.Errorf("unpacking archive: gzip: invalid header"), FailureUnpack},
		{"unknown error", fmt.Errorf("something novel"), FailureUnknown},
		{"wrapped timeout", fmt.Errorf("fetching module: %w", context.DeadlineExceeded), FailureTimeout},
		{"wrapped budget", fmt.Errorf("module package rejected: %w", &BudgetExceededError{Gate: "acquisition"}), FailureBudgetExceeded},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, ClassifyFailure(tc.err))
		})
	}
}

func TestClassifyDetailedFailureCodes(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"typed versions 404", registryEndpointError("versions", "https://registry.example/modules/versions", http.StatusNotFound, nil), FailureRegistryModuleNotFound},
		{"typed download 404", registryEndpointError("download", "https://registry.example/modules/1.0.0/download", http.StatusNotFound, nil), FailureRegistryVersionNotFound},
		{"typed HTTP ignores URL text", registryEndpointError("download", "https://registry.example/timeout-archive/download", http.StatusServiceUnavailable, nil), FailureHTTPServer},
		{"empty source", tfmodules.ValidateModuleSource(""), FailureEmptySource},
		{"wrapped empty source", fmt.Errorf("preparing declaration: %w", tfmodules.ValidateModuleSource("")), FailureEmptySource},
		{"SCI missing repo or ref", &tfmodules.UnresolvedError{Reason: "git ref not found through SCI: NotFound"}, FailureGitRepoOrRefNotFound},
		{"wrapped SCI missing repo or ref", fmt.Errorf("resolving module: %w", &tfmodules.UnresolvedError{Reason: "git ref not found through SCI: NotFound"}), FailureGitRepoOrRefNotFound},
		{"SCI ref not advertised", errors.New("git ref not advertised through SCI"), FailureGitRefNotFound},
		{"SCI ref could not be resolved", errors.New("git ref could not be resolved through SCI"), FailureGitRefNotFound},
		{"structured external git ref", &tfmodules.UnresolvedError{Reason: "broker rejected revision", FailureClass: tfmodules.FailureClassGitRefNotFound}, FailureGitRefNotFound},
		{"unbounded external class", &tfmodules.UnresolvedError{Reason: "novel broker error", FailureClass: "private_failure_code"}, FailureUnknown},
		{"unbounded structured class does not inspect reason", &tfmodules.UnresolvedError{Reason: "git ref not found through SCI: NotFound", FailureClass: "private_failure_code", Disposition: tfmodules.ResolverDispositionTerminal}, FailureUnknown},
		{"structured disposition requires class", &tfmodules.UnresolvedError{Reason: "git ref not found through SCI: NotFound", Disposition: tfmodules.ResolverDispositionTerminal}, FailureUnknown},
		{"Git username prompt required", errors.New("fatal: could not read Username for 'https://github.com': terminal prompts disabled"), FailureGitAuthRequired},
		{"Git prompts disabled", errors.New("fatal: terminal prompts disabled"), FailureGitAuthRequired},
		{"broker unadvertised ref", errors.New("git ref not advertised: v1.2.3"), FailureGitRefNotFound},
		{"broker unadvertised reference", errors.New("git reference was not advertised"), FailureGitRefNotFound},
		{"git repository", errors.New("remote: Repository not found."), FailureGitRepoNotFound},
		{"git ref", errors.New("fatal: couldn't find remote ref main"), FailureGitRefNotFound},
		{"git subdir", fmt.Errorf("extracting selected module: %w", errArchivePathMissing), FailureGitSubdirNotFound},
		{"serialized git subdir", errors.New("git_archive: archive path unavailable"), FailureGitSubdirNotFound},
		{"broker subdir absent at ref", errors.New("module subdirectory is not in the repository at this ref"), FailureGitSubdirNotFound},
		{"broker subdir not found", errors.New("brokered module subdirectory was not found"), FailureGitSubdirNotFound},
		{"placeholder ref", errors.New("git ref not advertised: __SOURCE_REF__"), FailurePlaceholderRef},
		{"quoted placeholder ref", errors.New(`git ref "__SOURCE_REF__" not advertised`), FailurePlaceholderRef},
		{"ordinary ref", errors.New("git ref not advertised: __feature__"), FailureGitRefNotFound},
		{"serialized versions 404", errors.New("could not resolve version: versions endpoint returned HTTP 404"), FailureRegistryModuleNotFound},
		{"serialized download 404", errors.New("download endpoint https://registry.example/mod/1.0.0/download returned HTTP 404"), FailureRegistryVersionNotFound},
		{"unsatisfied registry constraint", errors.New(`no published version satisfies constraint ">= 9.0"`), FailureRegistryVersionNotFound},
		{"invalid registry constraint", errors.New(`invalid version constraint "latest"`), FailureInvalidVersion},
		{"local cache miss is not a missing remote", errors.New(`module "vpc" not found in .terraform/modules; module "vpc" not found in manifest`), FailureUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, ClassifyFailure(tc.err))
		})
	}
}

func TestClassifyFailureBoundsTypedMetadata(t *testing.T) {
	for _, class := range []string{
		FailureEmptySource, FailureHostNotAllowlisted, FailureRegistryModuleNotFound, FailureRegistryVersionNotFound,
		FailureInvalidVersion, FailureGitAuthRequired, FailureGitRepoNotFound, FailureGitRefNotFound, FailureGitSubdirNotFound,
		FailureGitRepoOrRefNotFound, FailurePlaceholderRef, FailureTimeout, FailureBudgetExceeded,
		FailureNotFound, FailureHTTPClient, FailureHTTPServer, FailureNetwork, FailureUnpack, FailureUnknown,
	} {
		t.Run(class, func(t *testing.T) {
			err := &resolutionError{FailureDetails: FailureDetails{Class: class}, cause: errors.New("unclassified fixture failure")}
			require.Equal(t, class, ClassifyFailure(fmt.Errorf("manifest failure: %w", err)))
		})
	}
	for _, class := range []string{"arbitrary repository/ref", "future_failure_class", ""} {
		err := &resolutionError{FailureDetails: FailureDetails{Class: class}, cause: errors.New("unclassified fixture failure")}
		require.Equal(t, FailureUnknown, ClassifyFailure(err), "unrecognized manifest metadata must not become a metric tag")
		require.Equal(t, FailureUnknown, DescribeFailure(err).Class, "logs must use the same bounded classification")
	}
	err := &resolutionError{FailureDetails: FailureDetails{Class: "allowlist_denied"}, cause: errors.New("legacy manifest failure")}
	require.Equal(t, FailureHostNotAllowlisted, ClassifyFailure(err))
}
