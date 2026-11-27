/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package ruletest provides authoring-time verification helpers for IaC rules,
// including automated unknown-attribute mutation checks that run in CI and rule
// tests without adding production scan overhead.
package ruletest

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

const (
	blockKindResource = "resource"
	blockKindData     = "data"
)

// UnknownMutation represents one copy of a Terraform HCL fixture where a
// single written attribute expression has been replaced by an unbound variable
// reference (`var.__dd_unknown_probe`), making its evaluated value Unknown.
type UnknownMutation struct {
	BlockType string
	BlockName string
	Attribute string
	Source    []byte
}

// MutateAttributesToUnknown generates one UnknownMutation per written
// non-meta attribute across all resource/data blocks in src. Rule test suites
// can evaluate each mutation to verify that replacing a checked attribute with
// an unknown expression never produces a false positive.
func MutateAttributesToUnknown(filename string, src []byte) ([]UnknownMutation, error) {
	file, diags := hclsyntax.ParseConfig(src, filename, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, fmt.Errorf("parsing fixture %s: %s", filename, diags.Error())
	}
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return nil, nil
	}

	probeDecl := unknownProbeDeclaration("__dd_unknown_probe")
	const probeExpr = "var.__dd_unknown_probe"

	var mutations []UnknownMutation
	for _, blk := range body.Blocks {
		if (blk.Type != blockKindResource && blk.Type != blockKindData) || len(blk.Labels) < 2 {
			continue
		}
		collectBodyMutations(src, blk.Labels[0], blk.Labels[1], "", blk.Body, probeExpr, probeDecl, &mutations)
	}
	return mutations, nil
}

type mutableAttrSite struct {
	path  string
	start int
	end   int
}

// nolint:gocyclo
func collectMutableAttrSites(src []byte, prefix string, body *hclsyntax.Body, out *[]mutableAttrSite) {
	if body == nil {
		return
	}
	names := sortedMutableAttrs(body, prefix == "")
	for _, name := range names {
		r := body.Attributes[name].Expr.Range()
		if r.Start.Byte < 0 || r.End.Byte > len(src) || r.Start.Byte >= r.End.Byte {
			continue
		}
		attrPath := name
		if prefix != "" {
			attrPath = prefix + "." + name
		}
		*out = append(*out, mutableAttrSite{path: attrPath, start: r.Start.Byte, end: r.End.Byte})
	}
	idxByType := map[string]int{}
	for _, nested := range body.Blocks {
		if prefix == "" && nested.Type == "lifecycle" {
			continue
		}
		if nested.Type == "dynamic" {
			if !dynamicblock.Is(nested) {
				continue
			}
			// Never mutate dynamic meta-attributes (for_each / iterator / labels);
			// recurse only into the generated content block body.
			genType := dynamicblock.GeneratedType(nested)
			content := dynamicblock.Content(nested)
			if genType == "" || content == nil {
				continue
			}
			pos := idxByType[genType]
			idxByType[genType] = pos + 1
			nextPrefix := genType + "." + strconv.Itoa(pos)
			if prefix != "" {
				nextPrefix = prefix + "." + nextPrefix
			}
			collectMutableAttrSites(src, nextPrefix, content, out)
			continue
		}
		pos := idxByType[nested.Type]
		idxByType[nested.Type] = pos + 1
		nextPrefix := nested.Type + "." + strconv.Itoa(pos)
		if prefix != "" {
			nextPrefix = prefix + "." + nextPrefix
		}
		collectMutableAttrSites(src, nextPrefix, nested.Body, out)
	}
}

func collectBodyMutations(
	src []byte,
	resType, resName, prefix string,
	body *hclsyntax.Body,
	probeExpr, probeDecl string,
	out *[]UnknownMutation,
) {
	var sites []mutableAttrSite
	collectMutableAttrSites(src, prefix, body, &sites)
	for _, site := range sites {
		mutated := make([]byte, 0, len(src)+len(probeExpr)+len(probeDecl))
		mutated = append(mutated, src[:site.start]...)
		mutated = appendUnknownExpression(mutated, probeExpr, src[site.start:site.end])
		mutated = append(mutated, src[site.end:]...)
		mutated = append(mutated, probeDecl...)
		*out = append(*out, UnknownMutation{
			BlockType: resType,
			BlockName: resName,
			Attribute: site.path,
			Source:    mutated,
		})
	}
}

// Keep subsequent source locations stable when replacing a multiline map,
// template, or JSON expression, so independent findings retain their identity.
func appendUnknownExpression(dst []byte, expression string, original []byte) []byte {
	dst = append(dst, expression...)
	for _, ch := range original {
		if ch == '\n' {
			dst = append(dst, '\n')
		}
	}
	return dst
}

func sortedMutableAttrs(body *hclsyntax.Body, topLevel bool) []string {
	names := make([]string, 0, len(body.Attributes))
	for name := range body.Attributes {
		if topLevel && (name == "count" || name == "for_each" || name == "provider" || name == "depends_on") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// JointUnknownMutation represents a fixture where multiple attributes on the
// same block are simultaneously replaced with distinct unbound variables,
// catching multi-unknown conjunctive exemption bugs in CI.
type JointUnknownMutation struct {
	BlockType  string
	BlockName  string
	Attributes []string
	Source     []byte
}

// MutateAttributePairsToUnknown generates pairwise simultaneous unknown
// mutations across top-level and nested block attributes for every resource or
// data block declaring at least 2 mutable attributes.
func MutateAttributePairsToUnknown(filename string, src []byte) ([]JointUnknownMutation, error) {
	file, diags := hclsyntax.ParseConfig(src, filename, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, fmt.Errorf("parsing fixture %s: %s", filename, diags.Error())
	}
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return nil, nil
	}

	var out []JointUnknownMutation
	for _, blk := range body.Blocks {
		if (blk.Type != blockKindResource && blk.Type != blockKindData) || len(blk.Labels) < 2 {
			continue
		}
		var sites []mutableAttrSite
		collectMutableAttrSites(src, "", blk.Body, &sites)
		for i := 0; i < len(sites); i++ {
			for j := i + 1; j < len(sites); j++ {
				a, b := sites[i], sites[j]
				if a.start > b.start {
					a, b = b, a
				}
				const exprA = "var.__dd_unknown_probe_a"
				const exprB = "var.__dd_unknown_probe_b"
				decls := unknownProbeDeclaration("__dd_unknown_probe_a") + unknownProbeDeclaration("__dd_unknown_probe_b")
				mutated := make([]byte, 0, len(src)+len(exprA)+len(exprB)+len(decls))
				mutated = append(mutated, src[:a.start]...)
				mutated = appendUnknownExpression(mutated, exprA, src[a.start:a.end])
				mutated = append(mutated, src[a.end:b.start]...)
				mutated = appendUnknownExpression(mutated, exprB, src[b.start:b.end])
				mutated = append(mutated, src[b.end:]...)
				mutated = append(mutated, decls...)
				out = append(out, JointUnknownMutation{
					BlockType:  blk.Labels[0],
					BlockName:  blk.Labels[1],
					Attributes: []string{a.path, b.path},
					Source:     mutated,
				})
			}
		}
	}
	return out, nil
}

func unknownProbeDeclaration(name string) string {
	return fmt.Sprintf("\nvariable %q {\n  type = any\n  description = \"Unknown mutation probe\"\n}\n", name)
}
