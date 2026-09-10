/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import (
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/modulegraph"
)

// WalkOptions carries scan context needed to attach Terraform module provenance
// to inventory entries, aligned with SARIF properties.module from PR #319.
type WalkOptions struct {
	Ctx             context.Context
	RepoPath        string
	ExtractionMap   map[string]model.ExtractedPathObject
	ResolvedModules []modulegraph.ResolvedModule
	// ParsedModules is the Terraform module index produced during the scan.
	// When set, inventory enrichment reuses it instead of re-parsing HCL.
	ParsedModules map[string]tfmodules.ParsedModule
}
