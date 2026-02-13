/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package helpers

import (
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

type ExitHandler struct {
	ShouldIgnore string
	ShouldFail   map[string]struct{}
}

func NewExitHandler() *ExitHandler {
	return &ExitHandler{
		ShouldIgnore: "",
		ShouldFail:   map[string]struct{}{},
	}
}

// ResultsExitCode calculate exit code base on severity of results, returns 0 if no results was reported
// nolint:gocritic
func ResultsExitCode(summary *model.Summary) (*ExitHandler, int) {
	exitHandler := NewExitHandler()
	return exitHandler, ResultsExitCodeWithConfig(exitHandler, summary)
}

func ResultsExitCodeWithConfig(config *ExitHandler, summary *model.Summary) int {
	// severityArr is needed to make sure 'for' cycle is made in an ordered fashion
	severityArr := []model.Severity{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "TRACE"}
	codeMap := map[model.Severity]int{"CRITICAL": 60, "HIGH": 50, "MEDIUM": 40, "LOW": 30, "INFO": 20, "TRACE": 0}
	exitMap := summary.SeverityCounters

	for _, severity := range severityArr {
		if _, reportSeverity := config.ShouldFail[strings.ToLower(string(severity))]; !reportSeverity {
			continue
		}
		if exitMap[severity] > 0 {
			return codeMap[severity]
		}
	}
	return 0
}

// ShowError returns true if should show error, otherwise returns false
func (config *ExitHandler) ShowError(kind string) bool {
	return strings.EqualFold(config.ShouldIgnore, "none") ||
		(!strings.EqualFold(config.ShouldIgnore, "all") && !strings.EqualFold(config.ShouldIgnore, kind))
}
