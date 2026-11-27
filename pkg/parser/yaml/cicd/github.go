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

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// githubStepGroup retains the declaration context needed to interpret a step.
// It is internal: rules keep reading their existing provider-native documents.
type githubStepGroup struct {
	job          map[string]interface{}
	steps        []interface{}
	defaultShell string
}

func githubStepGroups(doc model.Document) iter.Seq[githubStepGroup] {
	return func(yield func(githubStepGroup) bool) {
		workflowShell, workflowDefault := githubDefaultShell(doc)
		jobs, _ := doc["jobs"].(map[string]interface{})
		for id, value := range jobs {
			job, ok := value.(map[string]interface{})
			if !ok || id == "_dd_lines" {
				continue
			}
			steps, _ := job["steps"].([]interface{})
			shell, hasDefault := githubDefaultShell(job)
			if !hasDefault {
				switch {
				case workflowDefault:
					shell = workflowShell
				case job["container"] != nil:
					shell = sh
				default:
					shell = githubRunnerShell(job["runs-on"])
				}
			}
			if !yield(githubStepGroup{job: job, steps: steps, defaultShell: shell}) {
				return
			}
		}
		runs, _ := doc["runs"].(map[string]interface{})
		if runs["using"] == "composite" {
			steps, _ := runs["steps"].([]interface{})
			// Composite run steps require their own explicit shell.
			yield(githubStepGroup{steps: steps, defaultShell: ""})
		}
	}
}

// Handle provider-specific declaration context once, including reusable jobs
// without steps. Generic expressions have already been extracted from the source.
func enhanceGitHub(ctx context.Context, doc model.Document) {
	contextLogger := logger.FromContext(ctx)
	for group := range githubStepGroups(doc) {
		enhanceGitHubCondition(ctx, group.job)
		for _, value := range group.steps {
			step, ok := value.(map[string]interface{})
			if !ok {
				continue
			}
			enhanceGitHubCondition(ctx, step)
			if script, ok := step["run"].(string); ok {
				shell := group.defaultShell
				if declared, present := step["shell"]; present {
					shell, _ = declared.(string)
				}
				parsed := parseGitHubRunBlock(script, shell)
				if parsed.Error != nil {
					contextLogger.Debug().Err(parsed.Error).Msg("Incomplete CI shell analysis")
				}
				step["_parsed_run"] = parsed
			}
		}
	}
}

// Only job and step conditions allow implicit expression syntax. An env or
// input named "if" remains an ordinary string, as does every GitLab field.
func enhanceGitHubCondition(ctx context.Context, declaration map[string]interface{}) {
	condition, ok := declaration["if"].(string)
	if !ok || strings.TrimSpace(condition) == "" || strings.Contains(condition, "${{") {
		return
	}
	expr := ExpressionMatch{Expression: condition, Terminated: true}
	declaration[parsedExpressionsKeyPrefix+"if"] = []ParsedExpression{*parseExpression(ctx, expr)}
}

// Defaults are selected once per declaration group. An explicitly empty or
// invalid default remains empty rather than silently choosing another shell.
func githubDefaultShell(declaration map[string]interface{}) (string, bool) {
	defaults, _ := declaration["defaults"].(map[string]interface{})
	run, _ := defaults["run"].(map[string]interface{})
	shell, present := run["shell"]
	value, _ := shell.(string)
	return value, present
}

// Unresolved runners retain the legacy Bash candidate because current rules
// have no general Bash fallback. This does not establish the actual runner OS.
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
		if !expression.Terminated {
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
