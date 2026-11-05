/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/stretchr/testify/require"
)

func TestRegistryFailureDiagnosticsSurviveChain(t *testing.T) {
	for _, tc := range []struct {
		name, version, stage, class string
		status                      int
	}{
		{"missing module", "~> 5.0", "versions", FailureRegistryModuleNotFound, http.StatusNotFound},
		{"missing version", "v5.5.1", "download", FailureRegistryVersionNotFound, http.StatusNotFound},
		{"unsatisfied constraint", ">= 9.0", "versions", FailureRegistryVersionNotFound, http.StatusOK},
		{"invalid exact version", "latest", "versions", FailureInvalidVersion, http.StatusOK},
		{"server failure", "1.0", "download", FailureHTTPServer, http.StatusServiceUnavailable},
		{"forbidden", "1.0", "download", FailureHTTPClient, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache := NewRegistryCache(time.Second)
			var paths []string
			cache.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				paths = append(paths, req.URL.Path)
				status, body := http.StatusOK, `{"modules.v1":"/v1/modules/"}`
				if strings.HasSuffix(req.URL.Path, "/"+tc.stage) {
					status, body = tc.status, `{"modules":[{"versions":[{"version":"5.0.0"}]}]}`
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
			})
			getter := NewGoGetterResolver(&GoGetterConfig{RegistryCache: cache})
			chain := NewChainResolver(decliningResolver("not found in .terraform/modules (run terraform init)"), getter)
			_, err := chain.Resolve(t.Context(), &tfmodules.ParsedModule{Source: "acme/network/aws", Version: tc.version})
			require.Error(t, err)
			details := DescribeFailure(err)
			require.Equal(t, tc.class, details.Class)
			require.Equal(t, "registry_"+tc.stage, details.Stage)
			require.Equal(t, tc.status, details.HTTPStatus)
			require.Equal(t, "https://registry.terraform.io"+paths[len(paths)-1], details.RequestURL)
			require.NotContains(t, err.Error(), "terraform init")
			require.NotContains(t, strings.Join(paths, ";"), "/latest/download")
			if tc.stage == "download" {
				require.Contains(t, err.Error(), details.RequestURL)
			}
			require.Len(t, FailureAttempts(err), 1)
			require.Equal(t, details, FailureAttempts(err)[0].FailureDetails)
		})
	}
}

func TestRegistryHTTPStatusClassificationIgnoresURLText(t *testing.T) {
	err := registryEndpointError("download", "https://registry.example/acme/timeout-archive/aws/1.0.0/download",
		http.StatusServiceUnavailable, nil)
	require.Equal(t, FailureHTTPServer, DescribeFailure(err).Class)
}

func TestChainStopsAfterDefinitiveFailure(t *testing.T) {
	for _, err := range []error{
		registryEndpointError("versions", "https://registry.example/acme/network/aws/versions", http.StatusNotFound, nil),
		&tfmodules.UnresolvedError{Reason: "ref rejected", Disposition: tfmodules.ResolverDispositionTerminal},
	} {
		t.Run(DescribeFailure(err).Class, func(t *testing.T) {
			chain := NewChainResolver(failingResolver(err), fakeChainResolver(func(context.Context, *tfmodules.ParsedModule) (Resolution, error) {
				t.Fatal("definitive failures must not trigger anonymous git fallback")
				return Resolution{}, nil
			}))
			_, got := chain.Resolve(t.Context(), &tfmodules.ParsedModule{Source: "acme/network/aws"})
			require.ErrorIs(t, got, err)
		})
	}
}

func TestChainPreservesAttemptsAndCauses(t *testing.T) {
	_, err := NewChainResolver(
		decliningResolver("not a local module"),
		failingResolver(fmt.Errorf("first attempt: %w", context.DeadlineExceeded)),
		failingResolver(errors.New("second attempt failed")),
	).Resolve(t.Context(), &tfmodules.ParsedModule{Source: "acme/network/aws"})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	attempts := FailureAttempts(err)
	require.Len(t, attempts, 2)
	require.Equal(t, FailureTimeout, attempts[0].Class)
	require.Equal(t, "second attempt failed", attempts[1].Reason)
}

func TestChainPreservesAttemptsBeforeDefinitiveFailure(t *testing.T) {
	for _, terminal := range []error{

		gitResolutionError("git_archive", "https://example.com/acme/network", "v1", "modules/missing",
			fmt.Errorf("%w: %w", errArchivePathMissing, os.ErrNotExist)),
		registryEndpointError("download", "https://registry.example/acme/network/aws/1.0.0/download", http.StatusNotFound, nil),
		&tfmodules.UnresolvedError{Reason: "SCI refused the ref", Disposition: tfmodules.ResolverDispositionTerminal, FailureClass: FailureGitRefNotFound},
	} {
		t.Run(DescribeFailure(terminal).Class, func(t *testing.T) {
			outage := &tfmodules.UnresolvedError{Reason: "SCI unavailable: connection refused"}
			timedOut := fmt.Errorf("earlier attempt: %w", context.DeadlineExceeded)
			_, err := NewChainResolver(
				decliningResolver("not a local module"),
				failingResolver(outage),
				failingResolver(timedOut),
				failingResolver(terminal),
				fakeChainResolver(func(context.Context, *tfmodules.ParsedModule) (Resolution, error) {
					t.Fatal("definitive failure must stop further fallback")
					return Resolution{}, nil
				}),
			).Resolve(t.Context(), &tfmodules.ParsedModule{Source: "acme/network/aws"})
			require.ErrorIs(t, err, terminal)
			require.Equal(t, terminal.Error(), err.Error(), "the definitive failure remains the primary reason")
			require.Equal(t, DescribeFailure(terminal), DescribeFailure(err))
			require.Equal(t, ClassifyFailure(terminal), ClassifyFailure(err), "an earlier timeout must not replace the definitive diagnosis")
			want := append(FailureAttempts(outage), FailureAttempts(timedOut)...)
			want = append(want, FailureAttempts(terminal)...)
			require.Equal(t, want, FailureAttempts(err), "keep attempted resolvers in order, excluding declines")
			details := DescribeFailure(err)
			prefetched := NewPrefetchedResolver(&Manifest{Modules: map[string]ManifestEntry{
				"acme/network/aws": {
					Status: ManifestStatusUnresolved, Failure: err.Error(), FailureDetails: &details, FailureAttempts: FailureAttempts(err),
				},
			}})
			_, replayed := prefetched.Resolve(t.Context(), &tfmodules.ParsedModule{Source: "acme/network/aws"})
			require.Error(t, replayed)
			require.Equal(t, details, DescribeFailure(replayed))
			require.Equal(t, want, FailureAttempts(replayed), "manifest replay must retain the attempts and primary diagnosis")
		})
	}
}

func TestFailureAttemptsPreserveResolverContext(t *testing.T) {
	gitErr := gitResolutionError("git_archive", "https://example.com/acme/network", "v1", "modules/missing",
		fmt.Errorf("%w: %w", errArchivePathMissing, os.ErrNotExist))
	httpErr := registryEndpointError("versions", "https://registry.example/acme/network/aws/versions", 0,
		errors.Join(errors.New("dial tcp: connection refused"), errors.New("second address unavailable")))
	for _, diagnostic := range []error{gitErr, httpErr} {
		t.Run(DescribeFailure(diagnostic).Stage, func(t *testing.T) {
			wrapped := &tfmodules.UnresolvedError{Reason: diagnostic.Error(), Cause: diagnostic}
			for _, err := range []error{diagnostic, wrapped, fmt.Errorf("resolving module: %w", wrapped)} {
				attempts := FailureAttempts(err)
				require.Len(t, attempts, 1, "nested causes belong to one resolver operation")
				require.Equal(t, DescribeFailure(diagnostic), attempts[0].FailureDetails)
				require.Contains(t, attempts[0].Reason, diagnostic.Error())
			}
		})
	}
	_, chainErr := NewChainResolver(failingResolver(&tfmodules.UnresolvedError{Reason: gitErr.Error(), Cause: gitErr,
		Disposition: tfmodules.ResolverDispositionRetryable}), failingResolver(httpErr)).Resolve(
		t.Context(), &tfmodules.ParsedModule{Source: "acme/network/aws"})
	attempts := FailureAttempts(fmt.Errorf("resolver chain: %w", chainErr))
	require.Len(t, attempts, 2, "actual chain aggregates still expand into resolver attempts")
	require.Equal(t, DescribeFailure(gitErr), attempts[0].FailureDetails)
	require.Equal(t, gitErr.Error(), attempts[0].Reason)
	require.Equal(t, DescribeFailure(httpErr), attempts[1].FailureDetails)
	require.Equal(t, httpErr.Error(), attempts[1].Reason)
}

func TestLegacyErrorWordingCannotStopFallback(t *testing.T) {
	for _, message := range []string{
		"git ref not found through SCI: NotFound", "git ref not advertised through SCI",
		"repository not found", "download endpoint returned HTTP 404",
	} {
		t.Run(message, func(t *testing.T) {
			_, err := NewChainResolver(
				failingResolver(&tfmodules.UnresolvedError{Reason: message}),
				succeedingResolver("/module"),
			).Resolve(t.Context(), &tfmodules.ParsedModule{Source: "acme/network/aws"})
			require.NoError(t, err)
		})
	}
}

func TestManifestFailureDiagnosticsRoundTrip(t *testing.T) {
	const rawURL = "https://registry.example/v1/modules/acme/network/aws/5.5.1/download"
	err := registryEndpointError("download", rawURL, http.StatusNotFound, nil)
	details := DescribeFailure(err)
	manifestFile := filepath.Join(t.TempDir(), "modules.json")
	require.NoError(t, os.Mkdir(filepath.Join(filepath.Dir(manifestFile), "modules"), 0o755))
	data := fmt.Sprintf(`{
  "schema_version": 1,
  "root": "modules",
  "modules": [{
    "source": "acme/network/aws", "requested_version": "v5.5.1", "status": "unresolved",
    "failure": "download failed", "failure_details": {"class": %q, "stage": %q, "http_url": %q, "http_status_code": 404},
    "failure_attempts": [{"class": %q, "stage": %q, "http_url": %q, "http_status_code": 404, "reason": "download failed"}],
    "declarations": [{"filename": "main.tf", "line_start": 1, "line_end": 4, "module_name": "network"}]
  }]
}`, details.Class, details.Stage, rawURL, details.Class, details.Stage, rawURL)
	require.NoError(t, os.WriteFile(manifestFile, []byte(data), 0o644))
	manifest, err := LoadManifest(t.Context(), manifestFile)
	require.NoError(t, err)
	_, err = NewChainResolver(NewPrefetchedResolver(manifest)).Resolve(t.Context(), &tfmodules.ParsedModule{
		Source: "acme/network/aws", Version: "v5.5.1", Name: "network", FileName: "main.tf", DefLine: 1,
	})
	require.Error(t, err)
	require.Equal(t, details, DescribeFailure(err))
	require.Equal(t, details.Class, ClassifyFailure(err), "manifest diagnostics must retain their metric code")
	attempts := FailureAttempts(err)
	require.Len(t, attempts, 1)
	require.Equal(t, details, attempts[0].FailureDetails)
	require.Equal(t, "download failed", attempts[0].Reason)
}

func TestChainRejectsSourceLessDeclarations(t *testing.T) {
	chain := NewChainResolver(fakeScreener{t: t})
	for _, source := range []string{"", " \t\n"} {
		mod := &tfmodules.ParsedModule{Source: source}
		_, err := chain.Resolve(t.Context(), mod)
		require.ErrorIs(t, err, tfmodules.ErrEmptyModuleSource)
		require.Equal(t, FailureEmptySource, DescribeFailure(err).Class)
		require.ErrorIs(t, chain.Screen(t.Context(), mod), tfmodules.ErrEmptyModuleSource)
	}
}

func TestGitFailureDiagnostics(t *testing.T) {
	for _, tc := range []struct{ message, ref, class string }{
		{"remote: Repository not found.", "v1", FailureGitRepoNotFound},
		{"fatal: couldn't find remote ref v1", "v1", FailureGitRefNotFound},
		{"fatal: upload-pack: not our ref abc123", "abc123", FailureGitRefNotFound},
		{"fatal: couldn't find remote ref __SOURCE_REF__", "__SOURCE_REF__", FailurePlaceholderRef},
		{"fatal: couldn't find remote ref __feature__", "__feature__", FailureGitRefNotFound},
		{"dial tcp: connection refused", "main", FailureNetwork},
	} {
		t.Run(tc.message, func(t *testing.T) {
			err := gitResolutionError("git_fetch", "https://example.com/acme/network", tc.ref, "modules/private", errors.New(tc.message))
			require.Equal(t, tc.class, DescribeFailure(err).Class)
			require.Contains(t, err.Error(), tc.ref)
			require.Contains(t, err.Error(), "modules/private")
		})
	}
}

func TestLocalGitMissingSubdirDiagnostics(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "-q")
	gitDir, err := detectGitDir(t.Context(), repo)
	require.NoError(t, err)
	runGit(t, repo, "config", "user.email", "test@example.com")
	runGit(t, repo, "config", "user.name", "Test")
	runGit(t, repo, "remote", "add", "origin", "https://example.com/acme/network.git")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "main.tf"), []byte("# fixture"), 0o644))
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-qm", "fixture")
	runGit(t, repo, "tag", "v1")
	resolver := NewLocalGitRefResolver([]string{repo}, t.TempDir())
	_, err = resolver.Resolve(t.Context(), &tfmodules.ParsedModule{
		Source: "git::https://example.com/acme/network.git//modules/missing?ref=v1",
	})
	require.Error(t, err)
	require.Equal(t, FailureGitSubdirNotFound, DescribeFailure(err).Class)
	require.Equal(t, "git_archive", DescribeFailure(err).Stage)
	attempts := FailureAttempts(err)
	require.Len(t, attempts, 1)
	require.Equal(t, DescribeFailure(err), attempts[0].FailureDetails)
	require.Contains(t, attempts[0].Reason, "modules/missing")
	require.Contains(t, attempts[0].Reason, `ref "v1"`)
	require.Contains(t, attempts[0].Reason, fmt.Sprintf("repo %q", gitDir))
}

func TestExternalFailureMetadataDoesNotDependOnReason(t *testing.T) {
	for _, reason := range []string{"unavailable", "git ref not advertised: __TEMPLATE__"} {
		err := &tfmodules.UnresolvedError{Reason: reason, FailureClass: FailureGitRefNotFound,
			FailureStage: "sci_resolve_ref", Disposition: tfmodules.ResolverDispositionTerminal}
		require.Equal(t, FailureDetails{Class: FailureGitRefNotFound, Stage: "sci_resolve_ref"}, DescribeFailure(err))
	}
}

func TestExternalBrokerFailureClassesRemainDistinct(t *testing.T) {
	for _, code := range []string{FailureGitRefInvalid, FailureBrokerUnavailable} {
		err := &tfmodules.UnresolvedError{Reason: "wording is immaterial", FailureClass: code, FailureStage: "sci_resolve_ref"}
		require.Equal(t, code, ClassifyFailure(err))
	}
}

func TestJoinedExternalCausesStayOneResolverAttempt(t *testing.T) {
	err := &tfmodules.UnresolvedError{Reason: "external fetch operation failed", Cause: errors.Join(
		errors.New("first upstream cause"), errors.New("second upstream cause")),
		FailureClass: FailureBrokerUnavailable, FailureStage: "broker"}
	_, got := NewChainResolver(failingResolver(err), failingResolver(errors.New("second resolver failed"))).Resolve(
		t.Context(), &tfmodules.ParsedModule{Source: "acme/network/aws"})
	attempts := FailureAttempts(got)
	require.Len(t, attempts, 2)
	require.Equal(t, "external fetch operation failed", attempts[0].Reason)
	require.Equal(t, "broker", attempts[0].Stage)
	require.Equal(t, "second resolver failed", attempts[1].Reason)
}

func TestManifestReplayPreservesDisposition(t *testing.T) {
	for _, disposition := range []tfmodules.ResolverDisposition{tfmodules.ResolverDispositionTerminal, tfmodules.ResolverDispositionRetryable, ""} {
		t.Run(string(disposition), func(t *testing.T) {
			// Exercise the serialized v1 module and its conversion to a lookup entry.
			data, err := json.Marshal(ManifestModule{Source: "acme/network/aws", Status: ManifestStatusUnresolved,
				Failure: "arbitrary wording", FailureDisposition: disposition,
				Declarations: []ManifestDeclaration{{Filename: "main.tf", ModuleName: "network", LineStart: 1, LineEnd: 3}},
			})
			require.NoError(t, err)
			var module ManifestModule
			require.NoError(t, json.Unmarshal(data, &module))
			manifest := &Manifest{Modules: map[string]ManifestEntry{}, candidates: map[string][]manifestCandidate{}}
			_, err = manifest.addV1Entry(t.Context(), &module)
			require.NoError(t, err)
			called := false
			fallback := fakeChainResolver(func(context.Context, *tfmodules.ParsedModule) (Resolution, error) {
				called = true
				return Resolution{LocalPath: "fallback"}, nil
			})
			_, err = NewChainResolver(NewPrefetchedResolver(manifest), fallback).Resolve(t.Context(), &tfmodules.ParsedModule{Source: module.Source})
			if disposition == tfmodules.ResolverDispositionTerminal {
				require.Error(t, err)
				require.False(t, called)
				require.Equal(t, disposition, FailureDisposition(err))
			} else {
				require.NoError(t, err)
				require.True(t, called)
			}
		})
	}
}
