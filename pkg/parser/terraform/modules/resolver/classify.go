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
	"regexp"
	"strconv"
	"strings"
)

// Failure codes for module resolution telemetry. The set is intentionally
// bounded: consumers turn these into metric tags, so raw error strings must
// never be used. Keep in sync with the taxonomy in K9CODESEC-5303.
const (
	FailureTimeout         = "timeout"
	FailureBudgetExceeded  = "budget_exceeded"
	FailureAllowlistDenied = "allowlist_denied"
	FailureNotFound        = "registry_not_found"
	FailureHTTPClient      = "http_4xx"
	FailureHTTPServer      = "http_5xx"
	FailureNetwork         = "network"
	FailureUnpack          = "unpack_failed"
	FailureUnknown         = "unknown"
)

// httpStatusRe matches an "HTTP NNN" reference in a resolver error message.
// Registry and git errors are formatted as "returned HTTP %d".
var httpStatusRe = regexp.MustCompile(`http (\d{3})`)

// failureSubstrings maps stable substrings of resolver error messages to
// failure codes, in classification priority order. Substrings are kept
// deliberately specific: ChainResolver joins the errors of every attempted
// resolver, so a generic fragment (e.g. a bare "not found" from a local
// .terraform cache miss) would hijack the classification of the real
// failure that follows it in the joined message. Registry 404s are matched
// by their "HTTP 404" status, not by "not found" text.
var failureSubstrings = []struct {
	code  string
	match []string
}{
	// "allowlist" alone: every host-policy denial names --module-host-allowlist.
	// Do not also match "destination" — DNS/connection failures for allowed
	// hosts are wrapped as "resolving HTTP destination host ..." and must
	// fall through to the network rule.
	{FailureAllowlistDenied, []string{"allowlist"}},
	{FailureTimeout, []string{"deadline", "timeout"}},
	{FailureNotFound, []string{"http 404", "no versions published", "no parseable versions"}},
	{FailureNetwork, []string{"no such host", "connection refused", "connection reset", "eof", "dial"}},
	{FailureUnpack, []string{"unpack", "decompress", "archive", "gzip", "zip"}},
}

// ClassifyFailure maps a module resolution error to one of the bounded
// failure codes above. Typed errors are matched first; the remaining rules
// match stable substrings of error messages produced by the resolvers.
// Anything unrecognized maps to FailureUnknown rather than leaking error text.
func ClassifyFailure(err error) string {
	if err == nil {
		return ""
	}
	var budgetErr *BudgetExceededError
	if errors.As(err, &budgetErr) {
		return FailureBudgetExceeded
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return FailureTimeout
	}
	// Typed EOF before substring rules: "eof" as a substring is too greedy to
	// match safely against arbitrary error text.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return FailureNetwork
	}
	msg := strings.ToLower(err.Error())
	for _, rule := range failureSubstrings {
		for _, key := range rule.match {
			if strings.Contains(msg, key) {
				return rule.code
			}
		}
	}
	if code, ok := httpStatusIn(msg); ok {
		if code >= 400 && code < 500 {
			return FailureHTTPClient
		}
		if code >= 500 && code < 600 {
			return FailureHTTPServer
		}
	}
	return FailureUnknown
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
