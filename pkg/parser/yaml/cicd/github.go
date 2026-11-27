/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com) Copyright 2026 Datadog, Inc.
 */

package cicd

import (
	"context"
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
