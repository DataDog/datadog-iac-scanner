/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

// SourceLocation is a filename plus an inclusive line/column range.
type SourceLocation struct {
	Filename    string `json:"filename,omitempty"`
	LineStart   int    `json:"line_start,omitempty"`
	LineEnd     int    `json:"line_end,omitempty"`
	ColumnStart int    `json:"column_start,omitempty"`
	ColumnEnd   int    `json:"column_end,omitempty"`
}

// ModulePathHop is one module call on the path to a finding.
type ModulePathHop struct {
	Name         string         `json:"name,omitempty"`
	Source       string         `json:"source,omitempty"`
	SourceType   string         `json:"source_type,omitempty"`
	Version      string         `json:"version,omitempty"`
	CodeLocation SourceLocation `json:"code_location,omitempty"`
}

// ModuleAttribution carries module provenance for instantiated Terraform findings.
// CodeLocation is repo-relative on the customer-owned root module declaration.
type ModuleAttribution struct {
	Name               string          `json:"name,omitempty"`
	Source             string          `json:"source,omitempty"`
	SourceType         string          `json:"source_type,omitempty"`
	Version            string          `json:"version,omitempty"`
	DependencyType     string          `json:"dependency_type,omitempty"`
	CodeLocation       SourceLocation  `json:"-"`
	ModuleCodeLocation SourceLocation  `json:"code_location,omitempty"`
	ModulePath         []ModulePathHop `json:"module_path,omitempty"`
	ModuleCodeOwned    bool            `json:"-"`
}
