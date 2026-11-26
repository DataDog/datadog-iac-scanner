/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com) Copyright 2026 Datadog, Inc.
 */
package gitlab

import (
	"math"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/yamlnode"
	"gopkg.in/yaml.v3"
)

// Defaults copy missing keywords after extends; they never deep-merge a job's
// explicitly defined keyword. Hidden templates remain unchanged, so a child
// disabling inheritance cannot receive defaults through an intermediate parent.
func (s *FileState) applyDefaults(root *yaml.Node) {
	defaults := s.jobDefaults(root)
	if defaults == nil {
		return
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, job := root.Content[i], root.Content[i+1]
		if strings.HasPrefix(key.Value, ".") || !isJobNode(key.Value, job) {
			continue
		}
		selection := yamlnode.MappingValue(yamlnode.MappingValue(job, "inherit"), "default")
		bridge := isBridgeNode(job)
		var owned *yaml.Node
		for field := 0; field+1 < len(defaults.Content); field += 2 {
			name := defaults.Content[field].Value
			if (bridge && name != kwInterrupt) || !inheritDefault(selection, name) || yamlnode.MappingValue(job, name) != nil {
				continue
			}
			if owned == nil {
				owned = s.cloneJobForDefaults(job, len(defaults.Content))
				if owned == nil {
					return
				}
			}
			owned.Content = append(owned.Content, defaults.Content[field:field+2]...)
		}
		if owned != nil {
			root.Content[i+1] = owned
		}
	}
}

func isBridgeNode(job *yaml.Node) bool {
	return yamlnode.MappingValue(job, "trigger") != nil ||
		(yamlnode.MappingValue(job, "script") == nil && yamlnode.MappingValue(job, "run") == nil)
}

func (s *FileState) cloneJobForDefaults(job *yaml.Node, extra int) *yaml.Node {
	if extra < 0 || len(job.Content) > math.MaxInt-extra {
		ExceedLimit(s.ctx, "default content capacity overflow")
		return nil
	}
	capacity := len(job.Content) + extra
	if capacity > (math.MaxInt-nodeAllocationBytes)/pointerAllocationBytes {
		ExceedLimit(s.ctx, "default allocation size overflow")
		return nil
	}
	if !Reserve(s.ctx, 1, nodeAllocationBytes+capacity*pointerAllocationBytes) {
		return nil
	}
	cloned := *job
	cloned.Content = make([]*yaml.Node, 0, capacity)
	cloned.Content = append(cloned.Content, job.Content...)
	s.nodeOrigins[&cloned] = s.nodeOrigins[job]
	s.lineOverlays[&cloned] = s.lineOverlays[job]
	return &cloned
}

func inheritDefault(selection *yaml.Node, name string) bool {
	if selection == nil {
		return true
	}
	if selection.Kind == yaml.SequenceNode {
		for _, field := range selection.Content {
			if field.Kind == yaml.ScalarNode && field.Value == name {
				return true
			}
		}
		return false
	}
	return selection.Tag != yamlBoolTag || selection.Value != yamlFalse
}

func (s *FileState) jobDefaults(root *yaml.Node) *yaml.Node {
	out := &yaml.Node{Kind: yaml.MappingNode, Tag: yamlnode.MapTag}
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		if key.Value != kwDefault || value.Kind != yaml.MappingNode {
			continue
		}
		parent := s.mappingSourceMask(value, s.keyOverlays[key])
		for field := 0; field+1 < len(value.Content); field += 2 {
			if !defaultSectionKeywords[value.Content[field].Value] {
				continue
			}
			fieldKey := s.defaultFieldKey(value.Content[field], s.mappingFieldSource(value, field, parent))
			out.Content = append(out.Content, fieldKey, value.Content[field+1])
		}
	}
	// Deprecated global defaults have the same missing-key semantics; explicit
	// entries in default take precedence over their legacy global equivalents.
	for _, name := range []string{kwImage, kwServices, kwBeforeScript, kwAfterScript, kwCache} {
		if yamlnode.MappingValue(out, name) != nil {
			continue
		}
		for i := 0; i+1 < len(root.Content); i += 2 {
			if root.Content[i].Value == name {
				key := s.defaultFieldKey(root.Content[i], s.keyOverlays[root.Content[i]])
				out.Content = append(out.Content, key, root.Content[i+1])
				break
			}
		}
	}
	if len(out.Content) == 0 || !Reserve(s.ctx, 1, nodeAllocationBytes+len(out.Content)*pointerAllocationBytes) {
		return nil
	}
	return out
}

func (s *FileState) defaultFieldKey(key *yaml.Node, source *model.LineOverlay) *yaml.Node {
	mask := &model.LineOverlay{}
	if source != nil {
		*mask = *source
	}
	mask.InheritedDefault = true
	return s.keyWithSource(key, mask)
}
