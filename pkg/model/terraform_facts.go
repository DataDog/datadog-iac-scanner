/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2026 Datadog, Inc.
 */
package model

import "encoding/json"

const TerraformFactsPlatform = "terraform"

// TerraformDocumentFacts are additive evaluator facts for one existing OPA
// document. Coverage describes only whether these facts represent Terraform
// subjects evaluated for this OPA document. "complete" does not claim
// coverage of a root module, deployment unit, source tree, omitted instances,
// or absent subjects.
type TerraformDocumentFacts struct {
	Platform string                  `json:"platform"`
	Coverage TerraformFactCoverage   `json:"coverage"`
	Reasons  []string                `json:"reasons,omitempty"`
	Subjects []TerraformSubjectFacts `json:"subjects,omitempty"`
}

// TerraformSubjectFacts describe one evaluated resource or data instance.
type TerraformSubjectFacts struct {
	SourceDocumentID string                    `json:"source_document_id"`
	Path             TerraformFactPath         `json:"path"`
	Address          string                    `json:"address,omitempty"`
	AddressComplete  bool                      `json:"address_complete"`
	InstanceSet      TerraformFactCompleteness `json:"instance_set"`
	Values           []TerraformValueFact      `json:"values,omitempty"`
	ValuesTruncated  bool                      `json:"values_truncated,omitempty"`
}

// TerraformValueFacts reports captured values and whether the producer hit
// its explicit extraction budget. Truncation is independent from native value
// state and child membership.
type TerraformValueFacts struct {
	Values    []TerraformValueFact
	Truncated bool
}

// TerraformValueFact describes native evaluator state and its legacy document
// presentation without copying the value or its source expression.
type TerraformValueFact struct {
	Path         TerraformFactPath         `json:"path"`
	NativeState  TerraformNativeValueState `json:"native_state"`
	Presentation TerraformPresentation     `json:"presentation"`
	Children     TerraformChildrenState    `json:"children"`
}

type TerraformFactCoverage string

const (
	TerraformCoverageComplete   TerraformFactCoverage = "complete"
	TerraformCoverageIncomplete TerraformFactCoverage = "incomplete"
	TerraformCoverageUnproven   TerraformFactCoverage = "unproven"
)

type TerraformFactCompleteness string

const (
	TerraformCompletenessComplete   TerraformFactCompleteness = "complete"
	TerraformCompletenessIncomplete TerraformFactCompleteness = "incomplete"
	TerraformCompletenessUnproven   TerraformFactCompleteness = "unproven"
)

type TerraformNativeValueState string

const (
	TerraformNativeKnown   TerraformNativeValueState = "known"
	TerraformNativeNull    TerraformNativeValueState = "null"
	TerraformNativeUnknown TerraformNativeValueState = "unknown"
	TerraformNativePartial TerraformNativeValueState = "partial"
)

type TerraformPresentation string

const (
	TerraformPresentationNative TerraformPresentation = "native"
	// TerraformPresentationUnproven means the producer cannot establish whether
	// the existing document presentation preserves the native value's structure
	// and content.
	TerraformPresentationUnproven TerraformPresentation = "unproven"
	// TerraformPresentationAdapted means the legacy document adapter changed
	// structure or content, or an aggregate contains non-native descendants.
	// Child membership is reported separately by TerraformValueFact.Children.
	TerraformPresentationAdapted            TerraformPresentation = "adapted"
	TerraformPresentationManagedReference   TerraformPresentation = "managed_reference"
	TerraformPresentationSourceExpression   TerraformPresentation = "source_expression"
	TerraformPresentationUnknownPlaceholder TerraformPresentation = "unknown_placeholder"
)

type TerraformChildrenState string

const (
	TerraformChildrenClosed  TerraformChildrenState = "closed"
	TerraformChildrenOpen    TerraformChildrenState = "open"
	TerraformChildrenUnknown TerraformChildrenState = "unknown"
)

// TerraformFactPath addresses a subject or nested value in input.document.
// It reuses PathSegment so numeric-looking keys remain distinct from indices.
type TerraformFactPath []PathSegment

func TerraformKeySegment(key string) PathSegment { return PathSegment{Key: key} }

func TerraformIndexSegment(index int) PathSegment { return PathSegment{Index: index, IsIndex: true} }

func (path TerraformFactPath) MarshalJSON() ([]byte, error) {
	parts := make([]any, 0, len(path))
	for _, segment := range path {
		if segment.IsIndex {
			parts = append(parts, segment.Index)
		} else {
			parts = append(parts, segment.Key)
		}
	}
	return json.Marshal(parts)
}
