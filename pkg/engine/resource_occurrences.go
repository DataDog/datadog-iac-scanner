/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"slices"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/platforms"
)

// resolveResourceOccurrences is the inventory side of finding decoding. Use
// the rule's document and path, since the location can explain the result
// with source written in a different file.
func resolveResourceOccurrences(
	file *model.FileMetadata, path model.SourcePath, searchKey string, line int, override *model.TerraformOverrideFinding,
) []*model.ResourceOccurrence {
	occurrences := file.ResourceOccurrences
	if len(occurrences) == 0 {
		return nil
	}
	if file.Platform == platforms.Terraform {
		if override != nil {
			return terraformBlockOccurrences(occurrences, override.Block)
		}
		return terraformOccurrences(file, path, searchKey)
	}
	if path != nil {
		return structuredDocumentOccurrence(file, path)
	}
	return legacyDocumentOccurrence(file, searchKey, line)
}

func structuredDocumentOccurrence(file *model.FileMetadata, path model.SourcePath) []*model.ResourceOccurrence {
	if file.Platform == platforms.Ansible && len(path) > 0 && path[0].IsIndex {
		path = append(model.SourcePath{{Key: "playbooks"}}, path...)
	}
	for _, o := range file.ResourceOccurrences {
		if len(path) >= len(o.StructuralPath) && slices.Equal(path[:len(o.StructuralPath)], o.StructuralPath) {
			return []*model.ResourceOccurrence{o}
		}
	}
	return nil
}

func legacyDocumentOccurrence(file *model.FileMetadata, searchKey string, line int) []*model.ResourceOccurrence {
	occurrences := file.ResourceOccurrences
	parts, anchored := detector.LegacyPathComponents(searchKey)
	for _, o := range occurrences {
		if matchesLegacyPath(parts, o.StructuralPath) {
			return []*model.ResourceOccurrence{o}
		}
	}
	if len(parts) == 0 || anchored ||
		(file.Platform == platforms.CloudFormation && slices.Equal(parts, []string{"Resources"})) {
		if file.Platform == platforms.CloudFormation {
			return cloudFormationCollectionOccurrence(occurrences, line)
		}
		if o := legacySourceOccurrence(occurrences, line); o != nil {
			return []*model.ResourceOccurrence{o}
		}
	}
	return nil
}

func matchesLegacyPath(parts []string, path model.SourcePath) bool {
	if len(parts) < len(path) {
		return false
	}
	for i, segment := range path {
		key := segment.Key
		if segment.IsIndex {
			key = strconv.Itoa(segment.Index)
		}
		if parts[i] != key {
			return false
		}
	}
	return true
}

// legacySourceOccurrence selects an occurrence with unambiguous written
// provenance.
func legacySourceOccurrence(occurrences []*model.ResourceOccurrence, line int) *model.ResourceOccurrence {
	if line < 1 {
		return nil
	}
	var match *model.ResourceOccurrence
	for _, o := range occurrences {
		start, end := o.LegacySource.Start.Line, o.LegacySource.End.Line
		if start < 1 || line < start || line > end {
			continue
		}
		if match != nil {
			return nil
		}
		match = o
	}
	return match
}

// Generated CloudFormation IDs share the collection's compatibility line.
// Prefer the first logical ID there as the inventory did before loop spans.
func cloudFormationCollectionOccurrence(occurrences []*model.ResourceOccurrence, line int) []*model.ResourceOccurrence {
	if line < 1 {
		return nil
	}
	for _, o := range occurrences {
		if o.LegacyCollectionLine == line || (o.LegacySource.Start.Line == line && o.LegacySource.End.Line == line) {
			return []*model.ResourceOccurrence{o}
		}
	}
	if o := legacySourceOccurrence(occurrences, line); o != nil {
		return []*model.ResourceOccurrence{o}
	}
	return nil
}

func terraformOccurrences(file *model.FileMetadata, path model.SourcePath, key string) []*model.ResourceOccurrence {
	block, _ := overrideFindingPath(path, key)
	if path == nil {
		// The dotted form can wrap the label just like the bracketed form.
		// Leave the detector's written-location key untouched.
		block.Name = strings.TrimSuffix(strings.TrimPrefix(block.Name, "{{"), "}}")
	}
	if block.Type == "" || block.Name == "" {
		return nil
	}
	matched := terraformBlockOccurrences(file.ResourceOccurrences, block)
	if len(matched) == 0 && block.Kind == "" {
		block.Kind = dataRoot
		matched = terraformBlockOccurrences(file.ResourceOccurrences, block)
	}
	return matched
}

func terraformBlockOccurrences(occurrences []*model.ResourceOccurrence, block model.TerraformBlock) []*model.ResourceOccurrence {
	kind := block.Kind
	if kind == "" {
		kind = terraformResourceBlock
	}
	var matched []*model.ResourceOccurrence
	for _, o := range occurrences {
		path := o.StructuralPath
		if path[0].Key == kind && path[1].Key == block.Type && path[2].Key == block.Name {
			matched = append(matched, o)
		}
	}
	return matched
}

// callerOccurrences rebinds a finding on a shared rule document to the
// declaration instances of the caller whose document was deduplicated.
func callerOccurrences(source, caller []*model.ResourceOccurrence) []*model.ResourceOccurrence {
	var matched []*model.ResourceOccurrence
	for _, occurrence := range source {
		for _, candidate := range caller {
			if slices.Equal(occurrence.StructuralPath, candidate.StructuralPath) {
				matched = append(matched, candidate)
			}
		}
	}
	return matched
}
