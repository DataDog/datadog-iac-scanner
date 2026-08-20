/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"fmt"
	"os"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/open-policy-agent/opa/v1/ast"
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

// The two block kinds tracked per declared type rather than by kind alone.
const (
	blockKindResource = "resource"
	blockKindData     = "data"
)

// blockKindAnchors is the set of non-resource top-level blocks tracked by kind.
var blockKindAnchors = map[string]bool{
	"module": true, "provider": true, "terraform": true,
	"output": true, "variable": true, "locals": true,
}

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

// ruleAnchors collects what a rule reads, working from the parsed Rego rather
// than its text: only the AST distinguishes a literal block key from one chosen
// at evaluation time, and a Terraform `data` block from the `data.generic`
// library namespace.
//
// It returns ok=false when the rule's reach cannot be bounded — an unparseable
// rule, or one that indexes a block through a variable — in which case any
// collected set would be an under-approximation and the rule must always run.
func ruleAnchors(source string) (anchors map[string]bool, ok bool) {
	module, err := ast.ParseModuleWithOpts("rule.rego", source, ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		return nil, false
	}

	anchors = make(map[string]bool)
	bounded := true
	ast.WalkRefs(module, func(ref ast.Ref) bool {
		// A ref rooted at the `data` document addresses Rego, not Terraform, so
		// `data.generic.terraform` says nothing about the blocks a rule reads.
		if root, isVar := ref[0].Value.(ast.Var); isVar && root.Equal(ast.DefaultRootDocument.Value.(ast.Var)) {
			return false
		}
		for i := 1; i < len(ref); i++ {
			key, isString := ref[i].Value.(ast.String)
			if !isString {
				continue
			}
			switch kind := string(key); kind {
			case blockKindResource, blockKindData:
				typ, named := refStringAt(ref, i+1)
				if !named {
					// `resource[res]` or a bare `document.resource` handed to a
					// helper: the type is decided later, so nothing bounds it.
					bounded = false
					return true
				}
				if kind == blockKindResource {
					anchors[resourceAnchor(typ)] = true
				} else {
					anchors[dataAnchor(typ)] = true
				}
			default:
				if blockKindAnchors[kind] {
					anchors[blockAnchor(kind)] = true
				}
			}
		}
		return false
	})
	if !bounded {
		return nil, false
	}
	return anchors, true
}

// refStringAt reports the literal key at position i, if there is one.
func refStringAt(ref ast.Ref, i int) (string, bool) {
	if i >= len(ref) {
		return "", false
	}
	key, ok := ref[i].Value.(ast.String)
	if !ok {
		return "", false
	}
	return string(key), true
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
		// Only the Rego is parsed: InputData is JSON, and a rule that picks
		// block names out of it reaches them through a variable, which
		// ruleAnchors already reports as unbounded.
		anchors, ok := ruleAnchors(queries[i].Content)
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
