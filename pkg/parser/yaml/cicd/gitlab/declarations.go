/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com) Copyright 2026 Datadog, Inc.
 */

// Package gitlab provides source declaration views, without compiling pipelines.
package gitlab

import (
	"iter"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"gopkg.in/yaml.v3"
)

const (
	yamlStringTag = "!!str"
	scriptField   = "script"
	beforeScript  = "before_script"
	afterScript   = "after_script"
)

// Kind describes a written context, not whether it executes.
type Kind string

const (
	Job      Kind = "job"
	Template Kind = "template"
	Default  Kind = "default"
	Global   Kind = "global"
)

// Declaration borrows immutable source nodes for the duration of a source walk.
// Index is the original key's offset in the root mapping, for source attribution.
type Declaration struct {
	Name  string
	Kind  Kind
	Index int
	Key   *yaml.Node
	Value *yaml.Node
}

// Declarations retains source order and does not synthesize inherited jobs.
func Declarations(root *yaml.Node) iter.Seq[Declaration] {
	return func(yield func(Declaration) bool) {
		if root == nil || root.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i+1 < len(root.Content); i += 2 {
			key, value := root.Content[i], root.Content[i+1]
			if key.Kind != yaml.ScalarNode || key.Tag != yamlStringTag {
				continue
			}
			kind := Job
			switch {
			case strings.HasPrefix(key.Value, "."):
				kind = Template
			case key.Value == string(Default):
				kind = Default
			case globalKeyword(key.Value):
				kind = Global
			}
			// Keep the source node, including aliases and tags. Resolving a view must
			// never erase an unresolved construct or mutate the rule document.
			if !yield(Declaration{Name: key.Value, Kind: kind, Index: i, Key: key, Value: value}) {
				return
			}
		}
	}
}

// Mapping resolves only ordinary YAML aliases. It does not expand merge keys,
// includes, extends or GitLab !reference tags.
func (d Declaration) Mapping() *yaml.Node {
	node := aliasTarget(d.Value)
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	return node
}

// ScriptBlock preserves presence separately from shape and content.
type ScriptBlock struct {
	Field    string
	Path     model.SourcePath
	Node     *yaml.Node
	Segments []Segment
	Issues   []Issue
}

// Segment holds decoded YAML text and its original structural path. Node is
// the defining scalar; Use identifies an alias use, when there is one.
type Segment struct {
	Text string
	Path model.SourcePath
	Node *yaml.Node
	Use  *yaml.Node
}

// Issue identifies an unsupported shape while collecting declared script text.
type Issue struct {
	Path   model.SourcePath
	Node   *yaml.Node
	Reason string
}

// Scripts collects written fields only. Globals/defaults do not become jobs,
// and absent fields are not confused with explicitly empty arrays or strings.
func (d Declaration) Scripts() []ScriptBlock {
	mapping := d.Mapping()
	if mapping == nil || d.Kind == Global || mapping.ShortTag() != "!!map" {
		return nil
	}
	var blocks []ScriptBlock
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		key, node := mapping.Content[i], mapping.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != yamlStringTag {
			continue
		}
		if key.Value != scriptField && key.Value != beforeScript && key.Value != afterScript {
			continue
		}
		if d.Kind == Default && key.Value == scriptField {
			continue
		}
		path := model.SourcePath{{Key: d.Name}, {Key: key.Value}}
		block := ScriptBlock{Field: key.Value, Path: path, Node: node}
		var use *yaml.Node
		if d.Value.Kind == yaml.AliasNode {
			use = d.Value
		}
		collectSegments(node, path, use, make(map[*yaml.Node]bool), &block)
		blocks = append(blocks, block)
	}
	return blocks
}

// GlobalScript collects a legacy root script declaration, not a mapping field.
func (d Declaration) GlobalScript() (ScriptBlock, bool) {
	if d.Kind != Global || (d.Name != beforeScript && d.Name != afterScript) {
		return ScriptBlock{}, false
	}
	path := model.SourcePath{{Key: d.Name}}
	block := ScriptBlock{Field: d.Name, Path: path, Node: d.Value}
	collectSegments(d.Value, path, nil, make(map[*yaml.Node]bool), &block)
	return block, true
}

func collectSegments(node *yaml.Node, path model.SourcePath, use *yaml.Node, active map[*yaml.Node]bool, block *ScriptBlock) {
	reason := "unsupported script value"
	switch {
	case node == nil:
		reason = "missing alias target"
	case active[node]:
		reason = "cyclic script alias"
	case node.Kind == yaml.AliasNode:
		active[node] = true
		defer delete(active, node)
		if use == nil {
			use = node
		}
		collectSegments(node.Alias, path, use, active, block)
		return
	case node.Kind == yaml.ScalarNode && node.ShortTag() == yamlStringTag:
		block.Segments = append(block.Segments, Segment{Text: node.Value, Path: append(model.SourcePath(nil), path...), Node: node, Use: use})
		return
	case node.Kind == yaml.SequenceNode && node.ShortTag() == "!!seq":
		active[node] = true
		defer delete(active, node)
		for i, child := range node.Content {
			length := len(path)
			path = append(path, model.PathSegment{Index: i, IsIndex: true})
			collectSegments(child, path, use, active, block)
			path = path[:length]
		}
		return
	}
	block.Issues = append(block.Issues, Issue{Path: append(model.SourcePath(nil), path...), Node: node, Reason: reason})
}

func aliasTarget(node *yaml.Node) *yaml.Node {
	seen := make(map[*yaml.Node]bool)
	for node != nil && node.Kind == yaml.AliasNode {
		if seen[node] {
			return nil
		}
		seen[node] = true
		node = node.Alias
	}
	return node
}

// Global/header keywords, including deprecated global job defaults. Job-level
// keywords such as release, artifacts and hooks remain valid declaration names.
func globalKeyword(key string) bool {
	switch key {
	case string(Default), "include", "stages", "variables", "workflow", "spec",
		"image", "services", "cache", beforeScript, afterScript, "types":
		return true
	}
	return false
}
