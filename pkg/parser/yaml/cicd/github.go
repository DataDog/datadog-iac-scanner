/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com) Copyright 2026 Datadog, Inc.
 */

package cicd

import (
	"context"
	"fmt"
	"iter"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// githubStepGroup retains the declaration context needed to interpret a step.
// It is internal: rules keep reading their existing provider-native documents.
type githubStepGroup struct {
	job   map[string]interface{}
	steps []interface{}
}

func githubStepGroups(doc model.Document) iter.Seq[githubStepGroup] {
	return func(yield func(githubStepGroup) bool) {
		jobs, _ := doc["jobs"].(map[string]interface{})
		for _, value := range jobs {
			job, _ := value.(map[string]interface{})
			if steps, ok := job["steps"].([]interface{}); ok {
				if !yield(githubStepGroup{job: job, steps: steps}) {
					return
				}
			}
		}
		runs, _ := doc["runs"].(map[string]interface{})
		if runs["using"] == "composite" {
			if steps, ok := runs["steps"].([]interface{}); ok {
				yield(githubStepGroup{steps: steps})
			}
		}
	}
}

// Only conditions on jobs and steps allow implicit expression syntax. An env
// or input named "if" remains an ordinary string, as does every GitLab field.
func enhanceGitHubConditions(ctx context.Context, doc model.Document) {
	jobs, _ := doc["jobs"].(map[string]interface{})
	for _, value := range jobs {
		job, _ := value.(map[string]interface{})
		enhanceGitHubCondition(ctx, job)
	}
	for group := range githubStepGroups(doc) {
		for _, value := range group.steps {
			step, _ := value.(map[string]interface{})
			enhanceGitHubCondition(ctx, step)
		}
	}
}

func enhanceGitHubCondition(ctx context.Context, declaration map[string]interface{}) {
	condition, ok := declaration["if"].(string)
	if !ok || strings.TrimSpace(condition) == "" || strings.Contains(condition, "${{") {
		return
	}
	expr := ExpressionMatch{Expression: condition, Full: "${{ " + condition + " }}"}
	declaration[parsedExpressionsKeyPrefix+"if"] = []ParsedExpression{*parseExpression(ctx, expr)}
}

// Shell selection belongs to the provider, not the shell parser. Unresolved
// runners retain the legacy Bash candidate: existing rules have no general
// Bash fallback, so disabling that candidate would lose security findings.
func githubShell(doc model.Document, job, step map[string]interface{}) string {
	if shell, present := step["shell"]; present {
		value, _ := shell.(string)
		return value
	}
	// Composite run steps require an explicit shell.
	if job == nil {
		return ""
	}
	for _, declaration := range []map[string]interface{}{job, doc} {
		defaults, _ := declaration["defaults"].(map[string]interface{})
		run, _ := defaults["run"].(map[string]interface{})
		if shell, present := run["shell"]; present {
			value, _ := shell.(string)
			return value
		}
	}
	if job["container"] != nil {
		return sh
	}
	return githubRunnerShell(job["runs-on"])
}

func githubRunnerShell(runner interface{}) string {
	if config, ok := runner.(map[string]interface{}); ok {
		runner = config["labels"]
	}
	labels, ok := runner.([]interface{})
	if !ok {
		labels = []interface{}{runner}
	}
	shell := ""
	for _, label := range labels {
		name, _ := label.(string)
		if strings.Contains(name, "${{") {
			continue
		}
		candidate := ""
		switch {
		case name == "windows", name == "windows-latest", name == "windows-2022", name == "windows-2025":
			candidate = pwsh
		case name == "linux", name == "macOS", strings.HasPrefix(name, "ubuntu-"), strings.HasPrefix(name, "macos-"):
			candidate = bash_shell
		}
		if candidate != "" {
			if shell != "" && candidate != shell {
				return bash_shell
			}
			shell = candidate
		}
	}
	if shell == "" {
		return bash_shell
	}
	return shell
}

// Expressions are substituted by GitHub before shell execution. Mask them for
// syntactic parsing without evaluating them, retaining byte offsets so command
// arguments still contain the original text seen by security rules.
func parseGitHubRunBlock(script, shell string) *ParsedRun {
	expressions := extractExpressionsFromString(script)
	if len(expressions) == 0 {
		return parseRunBlock(script, shell)
	}
	source := []byte(script)
	for _, expression := range expressions {
		for i := expression.FullSpan.Start; i < expression.FullSpan.End; i++ {
			source[i] = '_'
		}
	}
	parsed := parseShellSource(script, shell, source)
	markGitHubScriptExpressions(parsed.Commands)
	for _, expression := range expressions {
		if !strings.HasSuffix(expression.Full, "}}") {
			parsed.ParseOK = false
			parsed.Error = fmt.Errorf("unterminated GitHub Actions expression in script")
		}
	}
	return parsed
}

func markGitHubScriptExpressions(commands []ParsedCommand) {
	for i := range commands {
		cmd := &commands[i]
		for j := range cmd.Args {
			markGitHubScriptArg(&cmd.Args[j])
		}
		if cmd.Redirect != nil {
			markGitHubScriptArg(&cmd.Redirect.Target)
		}
		markGitHubScriptExpressions(cmd.Pipeline)
	}
}

func markGitHubScriptArg(arg *ParsedArg) {
	if strings.Contains(arg.Value, "${{") {
		arg.Type = string_with_expansion
		arg.Var = "" // A template is not a shell variable.
	}
}
