package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/DataDog/datadog-iac-scanner/pkg/scan"
	cli "github.com/urfave/cli/v3"
)

var customAction = &cli.Command{
	Name:  "custom",
	Usage: "Run or validate a custom Rego rule against an IaC file",
	Commands: []*cli.Command{
		evaluateCustomAction,
		validateCustomAction,
	},
}

type evaluateOutput struct {
	Findings []customFinding            `json:"findings"`
	Errors   []scan.RegoValidationError `json:"errors"`
}

type customFinding struct {
	Resource     string `json:"resource"`
	StartLine    int    `json:"start_line"`
	EndLine      int    `json:"end_line"`
	ResourceType string `json:"resource_type"`
	ResourceName string `json:"resource_name"`
	Message      string `json:"message"`
}

var evaluateCustomAction = &cli.Command{
	Name:  "evaluate",
	Usage: "Run a custom Rego rule against a sample IaC file; outputs JSON to stdout",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "platform", Required: true, Usage: "IaC platform (e.g. terraform, kubernetes)"},
		&cli.StringFlag{Name: "rego", Required: true, Usage: "base64-encoded Rego rule content"},
		&cli.StringFlag{Name: "file", Required: true, Usage: "base64-encoded IaC file content"},
	},
	Action: runEvaluateCustom,
}

func runEvaluateCustom(ctx context.Context, c *cli.Command) error {
	platform := c.String("platform")

	regoBytes, err := base64.StdEncoding.DecodeString(c.String("rego"))
	if err != nil {
		return fmt.Errorf("decoding --rego: %w", err)
	}

	fileBytes, err := base64.StdEncoding.DecodeString(c.String("file"))
	if err != nil {
		return fmt.Errorf("decoding --file: %w", err)
	}

	// Validate before scanning: compile errors would otherwise produce empty findings with no explanation.
	validationErrs, err := scan.ValidateCustomRegoQuery(ctx, platform, string(regoBytes))
	if err != nil {
		return fmt.Errorf("validating custom query: %w", err)
	}
	if len(validationErrs) > 0 {
		return writeJSON(evaluateOutput{Findings: []customFinding{}, Errors: validationErrs})
	}

	vulns, failedQueries, err := scan.RunCustomRegoQuery(ctx, platform, string(regoBytes), fileBytes)
	if err != nil {
		return fmt.Errorf("running custom query: %w", err)
	}

	findings := make([]customFinding, 0, len(vulns))
	for i := range vulns {
		v := &vulns[i]
		startLine := v.VulnerabilityLocation.Start.Line
		endLine := v.VulnerabilityLocation.End.Line
		if startLine == 0 {
			startLine = v.Line
			endLine = v.Line
		}
		findings = append(findings, customFinding{
			Resource:     v.SearchKey,
			StartLine:    startLine,
			EndLine:      endLine,
			ResourceType: v.ResourceType,
			ResourceName: v.ResourceName,
		})
	}

	runtimeErrs := make([]scan.RegoValidationError, 0, len(failedQueries))
	for _, queryErr := range failedQueries {
		runtimeErrs = append(runtimeErrs, scan.RegoValidationError{
			Code:    "rego_runtime_error",
			Message: queryErr.Error(),
		})
	}

	return writeJSON(evaluateOutput{Findings: findings, Errors: runtimeErrs})
}

type validateOutput struct {
	Errors []scan.RegoValidationError `json:"errors"`
}

var validateCustomAction = &cli.Command{
	Name:  "validate",
	Usage: "Compile-check a custom Rego rule; outputs JSON to stdout",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "platform", Required: true, Usage: "IaC platform (e.g. terraform, kubernetes)"},
		&cli.StringFlag{Name: "rego", Required: true, Usage: "base64-encoded Rego rule content"},
	},
	Action: runValidateCustom,
}

func runValidateCustom(ctx context.Context, c *cli.Command) error {
	regoBytes, err := base64.StdEncoding.DecodeString(c.String("rego"))
	if err != nil {
		return fmt.Errorf("decoding --rego: %w", err)
	}

	validationErrors, err := scan.ValidateCustomRegoQuery(ctx, c.String("platform"), string(regoBytes))
	if err != nil {
		return fmt.Errorf("validating custom query: %w", err)
	}

	if validationErrors == nil {
		validationErrors = []scan.RegoValidationError{}
	}

	return writeJSON(validateOutput{Errors: validationErrors})
}

func writeJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
