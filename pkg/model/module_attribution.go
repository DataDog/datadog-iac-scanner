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

// ModulePathHop is one module call on the path to a finding. Name and
// CodeLocation describe the module block as written in the caller's file,
// named from the scanned repository for the first hop and from the package the
// previous hop loaded otherwise. Source, SourceType and Version describe the
// module the block loads; a local module's source is its directory relative to
// the scanned repository, not the string as written.
type ModulePathHop struct {
	Name         string         `json:"name,omitempty"`
	Source       string         `json:"source,omitempty"`
	SourceType   string         `json:"source_type,omitempty"`
	Version      string         `json:"version,omitempty"`
	CodeLocation SourceLocation `json:"code_location,omitempty"`
}

// ModuleArgument binds a line range of a module resource to the root call-site
// argument whose value sets it.
type ModuleArgument struct {
	LineStart int
	LineEnd   int
	CallSite  SourceLocation
}

// ModuleAttribution carries module provenance for instantiated Terraform
// findings.
//
// CallSite is the call-site declaration the finding anchors on (SARIF primary
// location, IDE code bit): the root call argument setting the finding's value
// when it traces back to one, the root call's source argument otherwise.
//
// ModulePath lists the module calls from the root file down to the module
// holding the flagged resource, root first and never empty.
//
// ModuleCodeLocation is the flagged location inside the module loaded by the
// last hop. Its file name is relative to the root of Source, or to the scanned
// repository when SourceType is local.
//
// Source, SourceType and Version identify the repository or package holding
// that file: the package root without its subdirectory, the resolved registry
// version or the declared git ref (the resolved commit when none is declared).
// Source and Version are empty for local modules.
//
// DependencyType is direct for a single call and transitive for more.
type ModuleAttribution struct {
	Source             string           `json:"source,omitempty"`
	SourceType         string           `json:"source_type,omitempty"`
	Version            string           `json:"version,omitempty"`
	DependencyType     string           `json:"dependency_type,omitempty"`
	CallSite           SourceLocation   `json:"call_site,omitempty"`
	ModuleCodeLocation SourceLocation   `json:"code_location,omitempty"`
	ModulePath         []ModulePathHop  `json:"module_path,omitempty"`
	ModuleCodeOwned    bool             `json:"-"`
	Arguments          []ModuleArgument `json:"-"`
	// CallArgument is set when CallSite was narrowed to the argument whose
	// value the finding reads, so the value is set by the caller.
	CallArgument bool `json:"-"`
}
