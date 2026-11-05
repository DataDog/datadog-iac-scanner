/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com/)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

// Shared failure-code taxonomy for logs and ModuleStat.FailureCode, forwarded
// as module_prep.module_stats metric tags (K9CODESEC-5303). The set is bounded:
// never use error text, URLs, refs, or arbitrary manifest classes as codes.
// Keep canonicalFailureClass in sync when extending this taxonomy.
const (
	FailureTimeout                 = tfmodules.FailureClassTimeout
	FailureBudgetExceeded          = tfmodules.FailureClassBudgetExceeded
	FailureEmptySource             = tfmodules.FailureClassEmptySource
	FailureHostNotAllowlisted      = tfmodules.FailureClassHostNotAllowlisted
	FailureRegistryModuleNotFound  = tfmodules.FailureClassRegistryModuleNotFound
	FailureRegistryVersionNotFound = tfmodules.FailureClassRegistryVersionNotFound
	FailureInvalidVersion          = tfmodules.FailureClassInvalidVersion
	FailureGitAuthRequired         = tfmodules.FailureClassGitAuthRequired
	FailureGitRepoNotFound         = tfmodules.FailureClassGitRepoNotFound
	FailureGitRefNotFound          = tfmodules.FailureClassGitRefNotFound
	FailureGitRefInvalid           = tfmodules.FailureClassGitRefInvalid
	FailureBrokerUnavailable       = tfmodules.FailureClassBrokerUnavailable
	FailureGitSubdirNotFound       = tfmodules.FailureClassGitSubdirNotFound
	FailureGitRepoOrRefNotFound    = tfmodules.FailureClassGitRepoOrRefNotFound
	FailurePlaceholderRef          = tfmodules.FailureClassPlaceholderRef
	FailureHTTPClient              = tfmodules.FailureClassHTTPClient
	FailureHTTPServer              = tfmodules.FailureClassHTTPServer
	FailureNetwork                 = tfmodules.FailureClassNetwork
	FailureUnpack                  = tfmodules.FailureClassUnpack
	FailureUnknown                 = tfmodules.FailureClassUnknown
	// Legacy 404s that do not identify an endpoint cannot distinguish a missing
	// module (versions endpoint) from a missing version (download endpoint).
	FailureNotFound = tfmodules.FailureClassNotFound
	// Deprecated: use FailureHostNotAllowlisted. Retain the identifier for callers.
	FailureAllowlistDenied = FailureHostNotAllowlisted
)

const (
	gitRepositoryNotFoundMessage = "repository not found"
	gitRemoteRefNotFoundMessage  = "couldn't find remote ref"
)

// httpStatusRe matches an "HTTP NNN" reference in a resolver error message.
// Registry and git errors are formatted as "returned HTTP %d".
var httpStatusRe = regexp.MustCompile(`http (\d{3})`)

var registryNotFoundRe = regexp.MustCompile(`\b(versions|download) endpoint(?: \S+)? returned http 404\b`)
var gitRefNotAdvertisedRe = regexp.MustCompile(`\bgit (?:ref|reference)\b[^;\n]*\bnot advertised\b`)
var placeholderRefRe = regexp.MustCompile(`(?:\bref[ =:]+["']?|\bref not advertised: +)(__[A-Z0-9_]+__)`)

// failureSubstrings maps stable substrings of resolver error messages to
// failure codes, in classification priority order. Substrings are kept
// deliberately specific: ChainResolver joins the errors of every attempted
// resolver, so a generic fragment (e.g. a bare "not found" from a local
// .terraform cache miss) would hijack the classification of the real
// failure that follows it in the joined message.
var failureSubstrings = []struct {
	code  string
	match []string
}{
	{FailureEmptySource, []string{"module source is empty or missing"}},
	{FailureGitAuthRequired, []string{"could not read username", "terminal prompts disabled"}},
	{FailureGitRepoNotFound, []string{gitRepositoryNotFoundMessage, "git repo not found"}},
	{FailureGitRefNotFound, []string{
		"git ref not found", "git ref could not be resolved through sci", gitRemoteRefNotFoundMessage,
		"not our ref", "unadvertised object",
	}},
	{FailureGitSubdirNotFound, []string{
		"archive path unavailable", "git subdir not found", "git subdirectory not found",
		"module subdirectory is not in the repository at this ref", "brokered module subdirectory was not found",
	}},
	{FailureRegistryVersionNotFound, []string{"no versions published", "no parseable versions", "no published version satisfies constraint"}},
	{FailureInvalidVersion, []string{"invalid version constraint"}},
	{FailureTimeout, []string{"deadline", "timeout"}},
	{FailureNetwork, []string{"no such host", "connection refused", "connection reset", "eof", "dial"}},
	{FailureUnpack, []string{"unpack", "decompress", "archive", "gzip", "zip"}},
}

// ClassifyFailure maps a module resolution error to one of the bounded
// failure codes above. Typed diagnostics take precedence over legacy message
// matching. Unknown manifest classes fall back to the same bounded rules.
func ClassifyFailure(err error) string {
	if err == nil {
		return ""
	}
	if class := typedFailureCode(err); class != "" {
		return class
	}
	class := legacyFailureCode(strings.ToLower(err.Error()))
	if (class == FailureGitRefNotFound || class == FailureGitRepoOrRefNotFound) && placeholderRefRe.MatchString(err.Error()) {
		return FailurePlaceholderRef
	}
	return class
}

func typedFailureCode(err error) string {
	var budgetErr *BudgetExceededError
	if errors.As(err, &budgetErr) {
		return FailureBudgetExceeded
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return FailureTimeout
	}
	var failure *resolutionError
	if errors.As(err, &failure) {
		if class := canonicalFailureClass(failure.Class); class != "" {
			return class
		}
	}
	var externalFailure *tfmodules.UnresolvedError
	if errors.As(err, &externalFailure) {
		if class := canonicalFailureClass(externalFailure.FailureClass); class != "" {
			return class
		}
		if externalFailure.FailureClass != "" || externalFailure.Disposition != "" {
			// Structured errors with missing or unrecognized classes stay bounded;
			// their descriptive reason must not become a metric code.
			return FailureUnknown
		}
	}
	if errors.Is(err, tfmodules.ErrEmptyModuleSource) {
		return FailureEmptySource
	}
	if errors.Is(err, errArchivePathMissing) {
		return FailureGitSubdirNotFound
	}
	// Typed EOF before substring rules: "eof" as a substring is too greedy to
	// match safely against arbitrary error text.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return FailureNetwork
	}
	return ""
}

func legacyFailureCode(msg string) string {
	// A DNS failure for an allowed destination must not match this policy rule.
	if strings.Contains(msg, "allowlist") {
		return FailureHostNotAllowlisted
	}
	if strings.Contains(msg, "git ref not found through sci: notfound") {
		return FailureGitRepoOrRefNotFound
	}
	if match := registryNotFoundRe.FindStringSubmatch(msg); match != nil {
		if match[1] == registryVersionsStage {
			return FailureRegistryModuleNotFound
		}
		return FailureRegistryVersionNotFound
	}
	if gitRefNotAdvertisedRe.MatchString(msg) {
		return FailureGitRefNotFound
	}
	for _, rule := range failureSubstrings {
		for _, key := range rule.match {
			if strings.Contains(msg, key) {
				return rule.code
			}
		}
	}
	if code, ok := httpStatusIn(msg); ok {
		if code == http.StatusNotFound {
			return FailureNotFound
		}
		if code >= 400 && code < 500 {
			return FailureHTTPClient
		}
		if code >= 500 && code < 600 {
			return FailureHTTPServer
		}
	}
	return FailureUnknown
}

// Manifests are input data: only recognized classes may become metric tags.
func canonicalFailureClass(class string) string {
	switch class {
	case FailureTimeout, FailureBudgetExceeded, FailureEmptySource, FailureHostNotAllowlisted,
		FailureRegistryModuleNotFound, FailureRegistryVersionNotFound, FailureInvalidVersion,
		FailureGitAuthRequired, FailureGitRepoNotFound, FailureGitRefNotFound, FailureGitRefInvalid, FailureBrokerUnavailable,
		FailureGitSubdirNotFound, FailureGitRepoOrRefNotFound,
		FailurePlaceholderRef, FailureHTTPClient, FailureHTTPServer, FailureNetwork, FailureUnpack, FailureUnknown, FailureNotFound:
		return class
	case "allowlist_denied":
		return FailureHostNotAllowlisted
	default:
		return ""
	}
}

// httpStatusIn extracts the first "HTTP NNN" status from msg, if any.
func httpStatusIn(msg string) (int, bool) {
	match := httpStatusRe.FindStringSubmatch(msg)
	if match == nil {
		return 0, false
	}
	code, err := strconv.Atoi(match[1])
	if err != nil {
		return 0, false
	}
	return code, true
}
