/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"encoding/json"
	"maps"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/jsonfilter/parser"
	"github.com/antlr4-go/antlr/v4"
)

// metricFilterType is the Terraform resource whose pattern attribute is a
// CloudWatch Logs filter pattern.
const metricFilterType = "aws_cloudwatch_log_metric_filter"

// ParseFilterPattern returns the parse tree of a CloudWatch Logs filter
// pattern as JSON text, or pattern itself when it does not parse.
func ParseFilterPattern(pattern string) string {
	lexer := parser.NewJSONFilterLexer(antlr.NewInputStream(pattern))
	errorListener := parser.NewCustomErrorListener()
	lexer.RemoveErrorListeners()
	lexer.AddErrorListener(errorListener)

	p := parser.NewJSONFilterParser(antlr.NewCommonTokenStream(lexer, antlr.TokenDefaultChannel))
	p.RemoveErrorListeners()
	p.AddErrorListener(errorListener)
	p.BuildParseTrees = true
	tree := p.Awsjsonfilter()
	if errorListener.HasErrors() {
		return pattern
	}

	parsed, err := json.Marshal(parser.NewJSONFilterPrinterVisitor().VisitAll(tree))
	if err != nil {
		return pattern
	}
	return string(parsed)
}

// parseMetricFilterPatterns replaces the pattern of every metric filter of
// doc by its parse tree. Documents share subtrees, so the maps on the way to
// a pattern are copied rather than written to.
func parseMetricFilterPatterns(doc model.Document) {
	resources, ok := asStringMap(doc["resource"])
	if !ok {
		return
	}
	filters, ok := asStringMap(resources[metricFilterType])
	if !ok {
		return
	}
	var parsedFilters map[string]interface{}
	for name, body := range filters {
		fields, ok := asStringMap(body)
		if !ok {
			continue
		}
		pattern, ok := fields["pattern"].(string)
		if !ok {
			continue
		}
		parsed := ParseFilterPattern(pattern)
		if parsed == pattern {
			continue
		}
		if parsedFilters == nil {
			parsedFilters = maps.Clone(filters)
		}
		fields = maps.Clone(fields)
		fields["pattern"] = parsed
		parsedFilters[name] = fields
	}
	if parsedFilters == nil {
		return
	}
	resources = maps.Clone(resources)
	resources[metricFilterType] = parsedFilters
	doc["resource"] = resources
}

// parseTerraformValues parses the metric filter patterns and certificate
// bodies of every Terraform document of the scan, as written and
// instantiated, once.
func parseTerraformValues(ctx context.Context, files model.FileMetadatas, moduleDocs []model.Document) {
	for _, f := range files {
		if f == nil {
			continue
		}
		switch f.Kind {
		case model.KindTerraform:
			parseMetricFilterPatterns(f.Document)
			parseCertificateBodies(ctx, f.Document, f.FilePath)
		case model.KindTerraformPlan:
			parseMetricFilterPatterns(f.Document)
			parseCertificateBodies(ctx, f.Document, "")
		}
	}
	for _, doc := range moduleDocs {
		parseMetricFilterPatterns(doc)
		file, _ := doc["file"].(string)
		parseCertificateBodies(ctx, doc, file)
	}
}
