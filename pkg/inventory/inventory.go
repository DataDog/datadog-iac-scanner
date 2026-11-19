/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package inventory builds the IaC resource inventory a scan writes next to
// its SARIF report: every resource the scan parsed, whether or not a rule
// fired on it, the outcome of every file the scan considered, and the links
// from findings to the resources they belong to.
//
// Optional fields are omitted when they have no value; a consumer reads an
// absent field as null.
package inventory

import "time"

// SchemaVersion is the version of the inventory format.
const SchemaVersion = "1"

// Scan status values.
const (
	// StatusComplete means every file the scan considered was parsed and every
	// remote source it needed was resolved.
	StatusComplete = "complete"
	// StatusPartial means at least one file failed or one source could not be
	// resolved, so some resources may be missing.
	StatusPartial = "partial"
)

// File status values.
const (
	FileScanned = "scanned"
	FileFailed  = "failed"
)

// Resource completeness values.
const (
	CompletenessComplete = "complete"
	// CompletenessInstanceUnresolved marks a block whose count or for_each
	// could not be evaluated: the row stands for the block, never for an
	// invented instance.
	CompletenessInstanceUnresolved = "instance_unresolved"
)

// Inventory is the document written for one scan.
type Inventory struct {
	SchemaVersion     string             `json:"schema_version"`
	ScanID            string             `json:"scan_id"`
	ScannerVersion    string             `json:"scanner_version"`
	ScannedAt         time.Time          `json:"scanned_at"`
	Repository        Repository         `json:"repository"`
	Status            string             `json:"status"`
	PlatformsScanned  []string           `json:"platforms_scanned"`
	Stats             Stats              `json:"stats"`
	Files             []File             `json:"files"`
	UnresolvedSources []UnresolvedSource `json:"unresolved_sources"`
	Resources         []Resource         `json:"resources"`
	FindingLinks      []FindingLink      `json:"finding_links"`
}

// Repository is the scanned repository as the scanner sees it. It is
// informative only: consumers take the repository identity from their own,
// trusted metadata.
type Repository struct {
	URL       string `json:"url,omitempty"`
	CommitSHA string `json:"commit_sha,omitempty"`
	Branch    string `json:"branch,omitempty"`
}

// Stats summarizes the inventory.
type Stats struct {
	Resources        int `json:"resources"`
	FilesFailed      int `json:"files_failed"`
	FindingsUnlinked int `json:"findings_unlinked"`
}

// File is the outcome of one file the scan considered.
type File struct {
	// Path is relative to the repository root, with slash separators.
	Path string `json:"path"`
	// Platform is absent when the file was never classified.
	Platform string `json:"platform,omitempty"`
	Status   string `json:"status"`
	// Reason explains a failed file.
	Reason string `json:"reason,omitempty"`
}

// UnresolvedSource is a source the scan needed but could not resolve, such as
// a remote Terraform module.
type UnresolvedSource struct {
	Platform string `json:"platform"`
	Source   string `json:"source"`
	Reason   string `json:"reason"`
}

// Resource is one inventory row.
type Resource struct {
	// ResourceRef identifies the resource within the repository:
	// "<root module>|<resource path>" for Terraform, "<file>|<resource path>"
	// for every other platform. Consumers derive their keys from it.
	ResourceRef  string `json:"resource_ref"`
	ResourcePath string `json:"resource_path"`
	Platform     string `json:"platform"`
	ResourceType string `json:"resource_type"`
	ResourceName string `json:"resource_name"`
	Provider     string `json:"provider,omitempty"`

	// File is relative to the repository root, with slash separators.
	File        string `json:"file"`
	LineStart   int    `json:"line_start"`
	LineEnd     int    `json:"line_end,omitempty"`
	ColumnStart int    `json:"column_start,omitempty"`
	ColumnEnd   int    `json:"column_end,omitempty"`

	ModuleCall           string `json:"module_call,omitempty"`
	ModuleSource         string `json:"module_source,omitempty"`
	ModuleSourceType     string `json:"module_source_type,omitempty"`
	ModuleVersion        string `json:"module_version,omitempty"`
	ModuleDependencyType string `json:"module_dependency_type,omitempty"`
	CallSiteFile         string `json:"call_site_file,omitempty"`
	CallSiteLineStart    int    `json:"call_site_line_start,omitempty"`
	CallSiteLineEnd      int    `json:"call_site_line_end,omitempty"`
	// ModulePath is the JSON encoding of the module call hops, for display.
	ModulePath string `json:"module_path,omitempty"`

	Completeness string `json:"completeness"`

	OriginGenerator    string `json:"origin_generator,omitempty"`
	OriginChartPath    string `json:"origin_chart_path,omitempty"`
	OriginChartName    string `json:"origin_chart_name,omitempty"`
	OriginChartVersion string `json:"origin_chart_version,omitempty"`
	OriginTemplate     string `json:"origin_template,omitempty"`
}

// FindingLink maps a finding, by its SARIF DATADOG_FINGERPRINT, to a resource.
// One fingerprint can map to several resources, and one resource to several
// fingerprints.
type FindingLink struct {
	FindingFingerprint string `json:"finding_fingerprint"`
	ResourceRef        string `json:"resource_ref"`
}
