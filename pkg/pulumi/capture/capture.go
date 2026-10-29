/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package capture defines the document produced by evaluating one Pulumi
// project × stack against the scanner's fake Pulumi engine.
//
// It is the contract between the evaluation step (package eval, which runs the
// program) and the conversion step (which turns the captured resources into a
// Terraform plan). Changing it is a format change: bump FormatVersion and
// update testdata/golden.json.
package capture

// FormatVersion is the version of the capture document format.
const FormatVersion = 1

// Value markers used inside Resource.Inputs and Invoke.Args. A property that is
// not set by the program is absent: the SDKs only send what the code defines.
const (
	// MarkerUnknown is a value that is not known before deployment, for
	// example an output of another resource: {"__dd_unknown": true}.
	MarkerUnknown = "__dd_unknown"
	// MarkerSecret is a secret value; its content is never captured: {"__dd_secret": true}.
	MarkerSecret = "__dd_secret"
	// MarkerResourceRef is a reference to another resource: {"__dd_ref": "<urn>"}.
	MarkerResourceRef = "__dd_ref"
	// MarkerAsset is a Pulumi asset (file, string or remote content): {"__dd_asset": true, "path": "..."}.
	MarkerAsset = "__dd_asset"
	// MarkerArchive is a Pulumi archive: {"__dd_archive": true, "path": "..."}.
	MarkerArchive = "__dd_archive"
)

// SyntheticStack is the stack name used when a project commits no stack file.
const SyntheticStack = "dd-scan"

// Document is the capture of one project × stack evaluation.
type Document struct {
	FormatVersion int    `json:"formatVersion"`
	Project       string `json:"project"`
	Stack         string `json:"stack"`
	// SyntheticStack is true when the project has no Pulumi.<stack>.yaml and
	// the evaluation used the synthetic stack "dd-scan".
	SyntheticStack bool   `json:"syntheticStack,omitempty"`
	Runtime        string `json:"runtime"`
	// ProjectDir is the directory that holds Pulumi.yaml, slash-separated and
	// relative to the scan root ("." for the root itself).
	ProjectDir string     `json:"projectDir"`
	Resources  []Resource `json:"resources"`
	Invokes    []Invoke   `json:"invokes,omitempty"`
	Reads      []Read     `json:"reads,omitempty"`
	Config     Config     `json:"config"`
	Result     Result     `json:"result"`
}

// Resource is one RegisterResource call made by the program.
type Resource struct {
	URN  string `json:"urn"`
	Type string `json:"type"`
	Name string `json:"name"`
	// Custom is false for component resources (logical groups, not scanned
	// themselves; their children are).
	Custom bool `json:"custom"`
	// Remote marks a component implemented by a provider plugin (multi-language
	// component). The fake engine does not construct its children.
	Remote   bool   `json:"remote,omitempty"`
	Parent   string `json:"parent,omitempty"`
	Provider string `json:"provider,omitempty"`
	// Inputs are the properties set by the program, with Pulumi wire names
	// (camelCase) and the value markers above.
	Inputs map[string]any `json:"inputs"`
	// PropertyDependencies maps an input property to the URNs it was computed from.
	PropertyDependencies map[string][]string `json:"propertyDependencies,omitempty"`
	// Dependencies are the URNs of the resource-level dependsOn option.
	Dependencies []string `json:"dependencies,omitempty"`
	Source       *Source  `json:"source,omitempty"`
}

// Source is the position of the constructor call in the user's code, as sent
// by the SDK (sourcePosition).
type Source struct {
	// URI is the value sent by the SDK.
	URI string `json:"uri"`
	// Path is slash-separated and relative to the scan root. It is empty when
	// the SDK reported a position outside the scan root (some Go provider SDKs
	// report a frame inside their own generated code); Line is then 0.
	Path   string `json:"path,omitempty"`
	Line   int    `json:"line,omitempty"`
	Column int    `json:"column,omitempty"`
}

// Invoke is one data-source call (for example aws.ec2.getAmi).
type Invoke struct {
	Token string         `json:"token"`
	Args  map[string]any `json:"args"`
	// Placeholder is true when the fake engine answered with schema-derived
	// placeholder values instead of an empty result.
	Placeholder bool    `json:"placeholder,omitempty"`
	Source      *Source `json:"source,omitempty"`
}

// Read is one ReadResource call (StackReference, Resource.get).
type Read struct {
	URN  string `json:"urn"`
	Type string `json:"type"`
	Name string `json:"name"`
	ID   string `json:"id,omitempty"`
}

// Config describes the stack configuration given to the program.
type Config struct {
	// Values are the non-secret configuration values, keyed "<namespace>:<key>",
	// encoded as Pulumi passes them (strings; objects and arrays as JSON).
	Values map[string]string `json:"values,omitempty"`
	// Placeholders are project keys the evaluation had to invent because the
	// stack did not set them (D18 partial evaluation).
	Placeholders []string `json:"placeholders,omitempty"`
	// ProviderDefaults are provider settings (for example aws:region) set to a
	// placeholder because the stack did not define them.
	ProviderDefaults []string `json:"providerDefaults,omitempty"`
	// Secrets are the keys whose value is secret; their value is a placeholder.
	Secrets []string `json:"secrets,omitempty"`
}

// Status is the outcome of an evaluation.
type Status string

const (
	// StatusEvaluated means the program ran to completion.
	StatusEvaluated Status = "evaluated"
	// StatusFailed means the program was started and did not complete.
	StatusFailed Status = "failed"
	// StatusSkipped means the program was not started (unsupported runtime or OS).
	StatusSkipped Status = "skipped"
)

// Reason explains a failed or skipped evaluation.
type Reason string

// Reasons, aligned with the PulumiStats reasons (D13) and the phase-0 taxonomy.
const (
	ReasonUnsupportedRuntime   Reason = "unsupported_runtime"
	ReasonOSUnsupported        Reason = "os_unsupported"
	ReasonRuntimeMissing       Reason = "runtime_missing"
	ReasonDepsMissing          Reason = "deps_missing"
	ReasonBuildFailed          Reason = "build_failed"
	ReasonConfigMissing        Reason = "config_missing"
	ReasonEnvMissing           Reason = "env_missing"
	ReasonNetworkAccess        Reason = "network_access"
	ReasonFileMissing          Reason = "file_missing"
	ReasonEngineUnsupportedRPC Reason = "engine_unsupported_rpc"
	ReasonTimeout              Reason = "timeout"
	ReasonResourceCap          Reason = "resource_cap"
	ReasonProgramError         Reason = "program_error"
)

// Details refine a Reason.
const (
	DetailSDKAPIMismatch   = "sdk_api_mismatch"
	DetailAfterInvoke      = "after_invoke"
	DetailDepsIncompatible = "deps_incompatible"
	DetailEntrypoint       = "entrypoint"
	// DetailRequiredInput is an SDK check of a required input that got no
	// value, often because it depends on a value the fake engine left unknown.
	DetailRequiredInput = "required_input"
)

// Result is the outcome of the evaluation of one project × stack.
type Result struct {
	Status Status `json:"status"`
	Reason Reason `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
	// Message is a one-line excerpt of the error, for diagnostics.
	Message string `json:"message,omitempty"`
	// Partial is true when the program ran with placeholder configuration values.
	Partial        bool  `json:"partial,omitempty"`
	Attempts       int   `json:"attempts,omitempty"`
	DurationMillis int64 `json:"durationMillis"`
}
