/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

const registryVersionsStage = "versions"
const registryDownloadStage = "download"

// FailureDetails identifies the failing operation without parsing its reason.
type FailureDetails struct {
	Class      string `json:"class"`
	Stage      string `json:"stage,omitempty"`
	RequestURL string `json:"http_url,omitempty"`
	HTTPStatus int    `json:"http_status_code,omitempty"`
}

type FailureAttempt struct {
	FailureDetails
	Reason string `json:"reason"`
}

type resolutionError struct {
	FailureDetails
	cause       error
	attempts    []FailureAttempt
	disposition tfmodules.ResolverDisposition
}

func (e *resolutionError) Error() string { return e.cause.Error() }
func (e *resolutionError) Unwrap() error { return e.cause }

// ResolverDisposition reports a decision made at the operation boundary.
// Failure classes and human-readable diagnostics never determine fallback.
func (e *resolutionError) ResolverDisposition() tfmodules.ResolverDisposition {
	if e.disposition != "" {
		return e.disposition
	}
	return tfmodules.ResolverDispositionRetryable
}

// DescribeFailure uses the shared metric classification, retaining operation
// details when the resolver supplied them.
func DescribeFailure(err error) FailureDetails {
	class := ClassifyFailure(err)
	var failure *resolutionError
	if errors.As(err, &failure) {
		details := failure.FailureDetails
		details.Class = class
		return details
	}
	var external *tfmodules.UnresolvedError
	if errors.As(err, &external) && external.FailureStage != "" {
		return FailureDetails{Class: class, Stage: external.FailureStage}
	}
	switch class {
	case FailureEmptySource:
		return FailureDetails{Class: FailureEmptySource, Stage: "declaration"}
	case FailureGitRepoOrRefNotFound:
		// Older external resolvers use the same NotFound for missing repos and
		// missing refs. Preserve that ambiguity instead of claiming a ref is absent.
		return FailureDetails{Class: FailureGitRepoOrRefNotFound, Stage: "sci_resolve_ref"}
	case FailureHostNotAllowlisted:
		return FailureDetails{Class: FailureHostNotAllowlisted, Stage: "policy"}
	}
	return FailureDetails{Class: class}
}

// DescribeModuleFailure adds facts from the declaration to the resolver's error.
func DescribeModuleFailure(source string, err error) FailureDetails {
	details := DescribeFailure(err)
	if details.Class == FailureGitRefNotFound || details.Class == FailureGitRepoOrRefNotFound {
		_, _, ref, ok := parseGitGetterSource(source)
		if ok && placeholderGitRef(ref) {
			details.Class = FailurePlaceholderRef
		}
	}
	return details
}

// FailureDisposition preserves an explicit resolver verdict through preparation.
// An absent legacy verdict remains absent; diagnostic text never supplies one.
func FailureDisposition(err error) tfmodules.ResolverDisposition {
	var budget *BudgetExceededError
	if errors.As(err, &budget) {
		return tfmodules.ResolverDispositionTerminal
	}
	disposition, _ := unresolvedDisposition(err)
	return disposition
}

// FailureAttempts preserves each attempted resolver as a separate diagnostic.
// Declines (local cache and manifest misses) are excluded by ChainResolver.
func FailureAttempts(err error) []FailureAttempt {
	if err == nil {
		return nil
	}
	// Only a resolver chain's explicit attempt list is expanded. A resolver
	// may join several underlying causes for one operation; those causes must
	// keep their operation context rather than masquerade as separate attempts.
	var failure *resolutionError
	if errors.As(err, &failure) && len(failure.attempts) > 0 {
		return append([]FailureAttempt(nil), failure.attempts...)
	}
	reason := err.Error()
	if unresolved, ok := err.(*tfmodules.UnresolvedError); ok { //nolint:errorlint
		reason = unresolved.Reason
	}
	return []FailureAttempt{{FailureDetails: DescribeFailure(err), Reason: reason}}
}

func registryEndpointError(stage, rawURL string, status int, err error) error {
	class := ClassifyFailure(err)
	if class == "" {
		class = FailureUnknown
	}
	if err == nil {
		err = fmt.Errorf("%s endpoint %s returned HTTP %d", stage, rawURL, status)
	} else {
		err = fmt.Errorf("%s endpoint %s: %w", stage, rawURL, err)
	}
	switch {
	case status >= http.StatusBadRequest && status < http.StatusInternalServerError:
		class = FailureHTTPClient
	case status >= http.StatusInternalServerError:
		class = FailureHTTPServer
	}
	if status == http.StatusNotFound {
		class = FailureNotFound
		switch stage {
		case registryVersionsStage:
			class = FailureRegistryModuleNotFound
		case registryDownloadStage:
			class = FailureRegistryVersionNotFound
		}
	}
	disposition := tfmodules.ResolverDispositionRetryable
	if status == http.StatusNotFound && (stage == registryVersionsStage || stage == registryDownloadStage) {
		disposition = tfmodules.ResolverDispositionTerminal
	}
	return &resolutionError{
		disposition:    disposition,
		FailureDetails: FailureDetails{Class: class, Stage: "registry_" + stage, RequestURL: rawURL, HTTPStatus: status},
		cause:          err,
	}
}

func registryVersionSelectionError(class, rawURL string, err error) error {
	return &resolutionError{
		disposition:    tfmodules.ResolverDispositionTerminal,
		FailureDetails: FailureDetails{Class: class, Stage: "registry_versions", RequestURL: rawURL, HTTPStatus: http.StatusOK},
		cause:          err,
	}
}

func gitResolutionError(stage, repo, ref, subdir string, err error) error {
	class := ClassifyFailure(err)
	// Attribute unresolved template refs without assuming that ordinary branch
	// names (e.g. "latest" or "main") are placeholders.
	if class == FailureGitRefNotFound && placeholderGitRef(ref) {
		class = FailurePlaceholderRef
	}
	disposition := tfmodules.ResolverDispositionRetryable
	if errors.Is(err, errArchivePathMissing) {
		disposition = tfmodules.ResolverDispositionTerminal
	}
	return &resolutionError{
		disposition:    disposition,
		FailureDetails: FailureDetails{Class: class, Stage: stage},
		cause:          fmt.Errorf("%s repo %q ref %q subdir %q: %w", stage, repo, ref, subdir, err),
	}
}

func placeholderGitRef(ref string) bool {
	if len(ref) <= len("____") || !strings.HasPrefix(ref, "__") || !strings.HasSuffix(ref, "__") {
		return false
	}
	for _, c := range ref {
		if c != '_' && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
