/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package eval

import (
	"regexp"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/pulumi/capture"
)

// Configuration errors that trigger a retry with a placeholder value.
var (
	missingConfig = regexp.MustCompile(`[Mm]issing required configuration variable '([^']+)'`)
	invalidConfig = regexp.MustCompile(`Configuration '([^']+)' value '[^']*' is not a valid|` +
		`unable to (?:parse|unmarshall?) (?:required )?configuration variable '([^']+)'`)
	// requiredByProgram is a program's own check, such as "myproj:dbName is required".
	requiredByProgram = regexp.MustCompile(`\b([A-Za-z][\w-]*:[A-Za-z][\w-]*) (?:is|must be) (?:required|set)\b`)
)

type pattern struct {
	re     *regexp.Regexp
	reason capture.Reason
	detail string
}

// programErrors classify a failed program from its output, first match wins.
// Each entry was seen in the phase-0 corpus.
var programErrors = []pattern{
	{regexp.MustCompile(`Descriptors cannot be created directly`), capture.ReasonDepsMissing, capture.DetailDepsIncompatible},
	{regexp.MustCompile(`ModuleNotFoundError|ImportError|No module named|Pulumi SDK has not been installed`), capture.ReasonDepsMissing, ""},
	{regexp.MustCompile(`Temporary failure in name resolution|Name or service not known|Network is unreachable|` +
		`Failed to establish a new connection|getaddrinfo|dial tcp|no such host|NewConnectionError`), capture.ReasonNetworkAccess, ""},
	{regexp.MustCompile(`\b[A-Z][A-Z0-9_]{2,} (?:must be set|is not set|not set)\b|KeyError: '[A-Z][A-Z0-9_]{2,}'`),
		capture.ReasonEnvMissing, ""},
	{regexp.MustCompile(`module 'pulumi_\w+[^']*' has no attribute|unexpected keyword argument|` +
		`AttributeError: '\w+' object has no attribute|panic: interface conversion`), capture.ReasonProgramError, capture.DetailSDKAPIMismatch},
	{regexp.MustCompile(`unable to find main python program`), capture.ReasonFileMissing, capture.DetailEntrypoint},
	{regexp.MustCompile(`FileNotFoundError|no such file or directory`), capture.ReasonFileMissing, ""},
	{regexp.MustCompile(`Missing required property '`), capture.ReasonProgramError, capture.DetailRequiredInput},
}

// buildErrors classify a failed go build.
var depsMissingBuild = regexp.MustCompile(`module lookup disabled by GOPROXY=off|missing go\.sum entry|` +
	`cannot find module providing package|no required module provides package|inconsistent vendoring|` +
	`is not in std|go: updates to go\.mod needed|reading .*go\.mod.*: no such file`)

// classifyProgram explains a failed run from its output and what it declared.
func classifyProgram(output string, hadInvokes bool, unimplemented []string) (reason capture.Reason, detail string) {
	if missingConfig.MatchString(output) || invalidConfig.MatchString(output) || requiredByProgram.MatchString(output) {
		return capture.ReasonConfigMissing, ""
	}
	for _, p := range programErrors {
		if p.re.MatchString(output) {
			return p.reason, p.detail
		}
	}
	if len(unimplemented) > 0 {
		return capture.ReasonEngineUnsupportedRPC, strings.Join(unimplemented, ",")
	}
	if hadInvokes {
		return capture.ReasonProgramError, capture.DetailAfterInvoke
	}
	return capture.ReasonProgramError, ""
}

func classifyBuild(output string) capture.Reason {
	if depsMissingBuild.MatchString(output) {
		return capture.ReasonDepsMissing
	}
	return capture.ReasonBuildFailed
}

var errorLine = regexp.MustCompile(`Error|Exception|panic:|error occurred|^\* |must be|is required|unable to|cannot|missing`)

// maxMessage bounds the message kept in the capture document.
const maxMessage = 240

// excerpt is the last line of the output that states the error.
func excerpt(output string) string {
	lines := strings.Split(output, "\n")
	last := ""
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if l == "" {
			continue
		}
		if last == "" {
			last = l
		}
		if errorLine.MatchString(l) && !strings.HasPrefix(l, "File ") {
			return truncate(l)
		}
	}
	return truncate(last)
}

func truncate(s string) string {
	if len(s) > maxMessage {
		return s[:maxMessage]
	}
	return s
}
