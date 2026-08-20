/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// EXPERIMENT: skip Terraform rules that read nothing the scan contains.
//
// Every rule is evaluated against every document, so a rule that reads a
// resource type no file declares still pays to enumerate the whole document
// array. Skipping those rules is only sound if what a rule can read is bounded
// from its text, which is the hard part: a rule that picks its type at
// evaluation time, or fires on a block that is not a resource, must always run.
//
// Gated on IAC_EXPERIMENTAL_RULE_PREFILTER so both paths can be measured from
// one binary.

// A rule is anchored on the blocks it reads: resource types, data source types,
// and whole block kinds such as `module` or `provider`. Anchors are namespaced
// so a resource type is not satisfied by a data source of the same name.
func resourceAnchor(typ string) string { return "resource:" + typ }
func dataAnchor(typ string) string     { return "data:" + typ }
func blockAnchor(kind string) string   { return "block:" + kind }

// documentBlockKinds are the non-resource top-level blocks a rule can be
// anchored on. `data` is excluded: it is tracked per data source type instead.
var documentBlockKinds = []string{"module", "provider", "terraform", "output", "variable", "locals"}

var (
	// A rule that indexes resources through a variable, as in
	// `input.document[i].resource[res][name]`, decides the type at evaluation
	// time and can therefore match anything.
	dynamicResourcePattern = regexp.MustCompile(`resource\[\s*[^"\s\]]`)
	// A rule that hands the whole resource map to a helper, as in
	// `settings_are_equal(document.resource, ...)`, can likewise reach any type.
	bareResourcePattern = regexp.MustCompile(`\.resource[^.\[_a-zA-Z0-9]`)
	// `data.generic` is the Rego library namespace, not a Terraform data source.
	dataSourcePattern = regexp.MustCompile(`\bdata\.([a-z][a-z0-9_]*)`)
	blockKindPattern  = regexp.MustCompile(
		`document(?:\[[^\]]*\])?\.(module|provider|terraform|output|variable|locals)\b`)
)

// presentAnchors collects every anchor the documents about to be evaluated can
// satisfy, so a rule reading none of them cannot produce a finding.
func presentAnchors(sets ...[]model.Document) map[string]bool {
	present := make(map[string]bool)
	for _, set := range sets {
		for _, doc := range set {
			if resources, ok := asStringMap(doc["resource"]); ok {
				for typ := range resources {
					present[resourceAnchor(typ)] = true
				}
			}
			if sources, ok := asStringMap(doc["data"]); ok {
				for typ := range sources {
					present[dataAnchor(typ)] = true
				}
			}
			for _, kind := range documentBlockKinds {
				if _, ok := doc[kind]; ok {
					present[blockAnchor(kind)] = true
				}
			}
		}
	}
	return present
}

// ruleAnchors collects what a rule reads. It returns ok=false when the rule
// selects blocks at evaluation time, which makes any collected set an
// under-approximation and the rule unsafe to skip.
func ruleAnchors(source string) (anchors map[string]bool, ok bool) {
	if dynamicResourcePattern.MatchString(source) || bareResourcePattern.MatchString(source) {
		return nil, false
	}
	anchors = make(map[string]bool)
	for _, pattern := range []*regexp.Regexp{resourceFieldPattern, resourceIndexPattern} {
		for _, m := range pattern.FindAllStringSubmatch(source, -1) {
			anchors[resourceAnchor(m[1])] = true
		}
	}
	for _, m := range dataSourcePattern.FindAllStringSubmatch(source, -1) {
		if m[1] == "generic" {
			continue
		}
		anchors[dataAnchor(m[1])] = true
	}
	for _, m := range blockKindPattern.FindAllStringSubmatch(source, -1) {
		anchors[blockAnchor(m[1])] = true
	}
	return anchors, true
}

func filterQueriesByPresentAnchors(
	queries []model.QueryMetadata, present map[string]bool,
) (kept []model.QueryMetadata, skipped int) {
	kept = make([]model.QueryMetadata, 0, len(queries))
	for i := range queries {
		if !strings.EqualFold(queries[i].Platform, "terraform") {
			kept = append(kept, queries[i])
			continue
		}
		anchors, ok := ruleAnchors(queries[i].Content + "\n" + queries[i].InputData)
		// Unknown or empty anchors mean the rule's reach cannot be bounded.
		if !ok || len(anchors) == 0 || anyAnchorPresent(anchors, present) {
			kept = append(kept, queries[i])
			continue
		}
		if dump := os.Getenv("IAC_EXPERIMENT_DUMP_RULE"); dump != "" &&
			strings.Contains(queries[i].Query, dump) {
			fmt.Printf("=== SKIPPED RULE %q\n%s\n=== ANCHORS %v\n",
				queries[i].Query, queries[i].Content, anchors)
		}
		skipped++
	}
	return kept, skipped
}

func anyAnchorPresent(anchors, present map[string]bool) bool {
	for anchor := range anchors {
		if present[anchor] {
			return true
		}
	}
	return false
}
