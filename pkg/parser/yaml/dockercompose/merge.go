/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package dockercompose

import (
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/yamlnode"
	"gopkg.in/yaml.v3"
)

// mergePolicy describes how sequence-valued keys combine during one kind
// of Compose merge: the file merge and the extends merge follow different
// rule sets in the Compose Specification.
type mergePolicy struct {
	// defaultUnion: sequences union (with duplicate removal) unless the key
	// is in replace (file merge: compose-go appends override entries to the
	// base sequence, skipping identical ones, except command, entrypoint and
	// healthcheck.test, which the latest file overrides).
	defaultUnion bool
	// replace: keys whose sequences are replaced even under defaultUnion
	// (matched by leaf name, so healthcheck.test is covered by "test").
	replace map[string]struct{}
	// unionDedup: keys unioned with duplicates removed ("unique key" lists).
	unionDedup map[string]struct{}
	// unionKeepDupes: keys unioned without duplicate removal (extends
	// list-syntax dns/dns_search/env_file/tmpfs).
	unionKeepDupes map[string]struct{}
	// entryMerge: "KEY=VALUE" sequences merged by key, overriding side wins
	// (environment in list syntax, for both merge kinds).
	entryMerge map[string]struct{}
}

// fileMergePolicy merges multiple compose files (compose-go override/merge):
// mappings merge recursively, environment entries merge by key, every other
// sequence is appended (identical entries skipped) — including ports/expose,
// which later dedup by their uniqueness keys — except command, entrypoint and
// healthcheck.test, which the overriding file replaces.
var fileMergePolicy = mergePolicy{
	defaultUnion: true,
	replace: map[string]struct{}{
		"command": {}, "entrypoint": {}, "test": {},
	},
	entryMerge: map[string]struct{}{
		"environment": {},
	},
}

// extendsMergePolicy merges an extends target into a service: cap_add,
// cap_drop, configs, device_cgroup_rules, expose, external_links, ports,
// secrets, security_opt (plus deploy.placement sequences, matched by leaf
// name) are unioned with dedup; list-syntax dns, dns_search, env_file, tmpfs
// union without dedup; environment entries merge by key; every other
// sequence is replaced (compose-go extends defaults to replacement).
var extendsMergePolicy = mergePolicy{
	unionDedup: map[string]struct{}{
		"cap_add": {}, "cap_drop": {}, "configs": {}, "constraints": {},
		"preferences": {}, "generic_resources": {}, "device_cgroup_rules": {},
		"expose": {}, "external_links": {}, "ports": {}, "secrets": {}, "security_opt": {},
	},
	unionKeepDupes: map[string]struct{}{
		"dns": {}, "dns_search": {}, "env_file": {}, "tmpfs": {},
	},
	entryMerge: map[string]struct{}{
		"environment": {},
	},
}

// mergeMappings merges override into base in place (override wins) per the
// Compose Specification: mappings merge recursively, sequences follow the
// policy, anything else is replaced. crossFile=true means override's nodes
// come from another file: replaced values keep the base node's position and
// appended entries are remapped to a base-file line, so findings stay in the
// file being scanned. With crossFile=false every node keeps its own position.
func mergeMappings(base, override *yaml.Node, crossFile bool, policy mergePolicy) {
	if base == nil || override == nil || base.Kind != yaml.MappingNode || override.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(override.Content); i += 2 {
		keyNode, valNode := override.Content[i], override.Content[i+1]
		key := keyNode.Value
		baseIdx := yamlnode.MappingKeyIndex(base, key)
		if baseIdx < 0 {
			// Key only in the override: append as-is with its own position.
			if crossFile {
				yamlnode.RewriteLines(keyNode, base.Line)
				yamlnode.RewriteLines(valNode, base.Line)
			}
			base.Content = append(base.Content, keyNode, valNode)
			continue
		}
		baseVal := base.Content[baseIdx+1]
		switch {
		case baseVal.Kind == yaml.MappingNode && valNode.Kind == yaml.MappingNode:
			mergeMappings(baseVal, valNode, crossFile, policy)
		case baseVal.Kind == yaml.SequenceNode && valNode.Kind == yaml.SequenceNode:
			mergeSequenceValues(baseVal, valNode, key, crossFile, policy)
		default:
			replaceWithPosition(baseVal, valNode, crossFile)
		}
	}
}

// mergeSequenceValues combines two sequences under the policy's rules for
// key (see mergePolicy for the rule sets).
func mergeSequenceValues(baseVal, valNode *yaml.Node, key string, crossFile bool, policy mergePolicy) {
	switch {
	case hasKey(policy.entryMerge, key):
		mergeEnvEntries(baseVal, valNode)
	case hasKey(policy.replace, key):
		replaceWithPosition(baseVal, valNode, crossFile)
	case policy.defaultUnion:
		unionSequences(baseVal, valNode, crossFile, true)
	case hasKey(policy.unionDedup, key):
		unionSequences(baseVal, valNode, crossFile, true)
	case hasKey(policy.unionKeepDupes, key):
		unionSequences(baseVal, valNode, crossFile, false)
	default:
		replaceWithPosition(baseVal, valNode, crossFile)
	}
}

func hasKey(set map[string]struct{}, key string) bool {
	_, ok := set[key]
	return ok
}

// replaceWithPosition copies valNode into baseNode; with crossFile=true the
// base node's position is kept (the declaration the value overrides),
// otherwise the winning node's own position is correct.
func replaceWithPosition(baseNode, valNode *yaml.Node, crossFile bool) {
	if !crossFile {
		*baseNode = *valNode
		return
	}
	line, column := baseNode.Line, baseNode.Column
	*baseNode = *valNode
	baseNode.Line, baseNode.Column = line, column
}

// unionSequences appends override's entries to base; with dedup=true only
// missing ones (scalars by value, non-scalars structurally); with crossFile
// appended entries are remapped to the base sequence's line.
func unionSequences(base, override *yaml.Node, crossFile, dedup bool) {
	if !dedup {
		for _, e := range override.Content {
			if crossFile {
				yamlnode.RewriteLines(e, base.Line)
			}
			base.Content = append(base.Content, e)
		}
		return
	}
	seen := make(map[string]struct{}, len(base.Content))
	var nonScalars []*yaml.Node
	for _, e := range base.Content {
		if e.Kind == yaml.ScalarNode {
			seen[e.Value] = struct{}{}
		} else {
			nonScalars = append(nonScalars, e)
		}
	}
	for _, e := range override.Content {
		if e.Kind == yaml.ScalarNode {
			if _, ok := seen[e.Value]; ok {
				continue
			}
			seen[e.Value] = struct{}{}
		} else {
			dup := false
			for _, b := range nonScalars {
				if yamlnode.Equal(b, e) {
					dup = true
					break
				}
			}
			if dup {
				continue
			}
			nonScalars = append(nonScalars, e)
		}
		if crossFile {
			yamlnode.RewriteLines(e, base.Line)
		}
		base.Content = append(base.Content, e)
	}
}

// mergeEnvEntries merges list-syntax "KEY=VALUE" environments by key,
// overriding entries winning; a bare overriding entry shadows the same key
// and stays bare for later env-file resolution.
func mergeEnvEntries(base, override *yaml.Node) {
	if base == nil || override == nil || base.Kind != yaml.SequenceNode || override.Kind != yaml.SequenceNode {
		return
	}
	overrideKeys := make(map[string]struct{}, len(override.Content))
	for _, e := range override.Content {
		if e.Kind == yaml.ScalarNode {
			overrideKeys[envEntryKey(e.Value)] = struct{}{}
		}
	}
	out := make([]*yaml.Node, 0, len(base.Content)+len(override.Content))
	for _, e := range base.Content {
		if e.Kind == yaml.ScalarNode {
			if _, shadowed := overrideKeys[envEntryKey(e.Value)]; shadowed {
				continue
			}
		}
		out = append(out, e)
	}
	out = append(out, override.Content...)
	base.Content = out
}

// envEntryKey returns the KEY of a "KEY=VALUE" entry, or the whole value
// for a bare entry.
func envEntryKey(entry string) string {
	if eq := strings.IndexByte(entry, '='); eq >= 0 {
		return entry[:eq]
	}
	return entry
}
