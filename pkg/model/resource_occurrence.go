/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

import (
	"cmp"
	"slices"
	"strconv"
	"strings"

	"github.com/zclconf/go-cty/cty"
)

// ResourceOccurrence is one parsed or evaluated declaration instance.
// The inventory row and its findings share this occurrence for the scan.
type ResourceOccurrence struct {
	DocumentID     string
	DocumentIndex  int
	StructuralPath SourcePath
	Platform       string
	File           string
	Source         ResourceLocation

	ResourcePath string
	ResourceType string
	ResourceName string
	Provider     string

	Helm      *HelmResourceOrigin
	Terraform *TerraformResourceOccurrence

	// LegacySource is the written span available for legacy location-only
	// results. A zero span means that only a structural path identifies
	// the occurrence, for example an item in a rendered Helm list.
	LegacySource ResourceLocation
	// Generated CloudFormation resources retain the collection's written
	// line for legacy collection-level results.
	LegacyCollectionLine int
}

type HelmResourceOrigin struct {
	ChartPath, ChartName, ChartVersion, Template string
}

type TerraformResourceOccurrence struct {
	Root        string
	Address     string
	ModuleCall  string
	Complete    bool
	CallChain   []TerraformCallSite
	Attribution *ModuleAttribution
}

// TerraformCallSite keeps the evaluator's typed call provenance without the
// evaluated bodies and scopes used to trace module arguments.
type TerraformCallSite struct {
	Name, Source, Version string
	InstanceKey           cty.Value
	File                  string
	Range                 ResourceLocation
}

// CompareOccurrencePaths preserves the order of dotted list indices used to
// assign suffixes to inventory rows whose written fields are identical.
func CompareOccurrencePaths(a, b SourcePath) int {
	return slices.CompareFunc(a, b, func(a, b PathSegment) int {
		if a.IsIndex && b.IsIndex {
			return strings.Compare(strconv.Itoa(a.Index), strconv.Itoa(b.Index))
		}
		return cmp.Or(cmp.Compare(a.Key, b.Key), cmp.Compare(a.Index, b.Index))
	})
}

// OccurrenceSet collects the resources a finding identity stands for,
// independently of which finding is kept for reporting.
type OccurrenceSet map[*ResourceOccurrence]struct{}

func (s OccurrenceSet) Add(v *Vulnerability) {
	for _, occurrence := range v.ResourceOccurrences {
		s[occurrence] = struct{}{}
	}
}

func (s OccurrenceSet) Assign(v *Vulnerability) {
	occurrences := make([]*ResourceOccurrence, 0, len(s))
	for occurrence := range s {
		occurrences = append(occurrences, occurrence)
	}
	slices.SortFunc(occurrences, func(a, b *ResourceOccurrence) int {
		if a.Terraform != nil && b.Terraform != nil {
			if order := cmp.Or(cmp.Compare(a.Terraform.Root, b.Terraform.Root),
				cmp.Compare(a.Terraform.Address, b.Terraform.Address)); order != 0 {
				return order
			}
		}
		return cmp.Or(cmp.Compare(a.DocumentID, b.DocumentID), CompareOccurrencePaths(a.StructuralPath, b.StructuralPath))
	})
	v.ResourceOccurrences = occurrences
}
