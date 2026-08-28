/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package inventory enumerates every IaC resource found during a scan,
// independent of whether any rule matched it.
package inventory

import (
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// BlockType is the category of block a resource originates from.
type BlockType string

const (
	BlockResource BlockType = "resource"
	BlockData     BlockType = "data"
	BlockModule   BlockType = "module"
	BlockManifest BlockType = "manifest"
	BlockTask     BlockType = "task"
	BlockStage    BlockType = "stage"
	BlockJob      BlockType = "job"
)

// Resource is a single IaC resource extracted from a parsed document.
type Resource struct {
	Platform      string
	BlockType     BlockType
	Type          string
	Name          string
	Provider      string
	File          string
	StartLine     int
	EndLine       int
	ModuleSource  string
	ModuleVersion string
	Module        *model.ModuleAttributionSARIF
	APIVersion    string
	Namespace     string
	// Attributes contains every declared attribute; annotation keys are stripped.
	// Nested blocks are maps; arrays are slices. No filtering is applied.
	Attributes map[string]interface{}
}
