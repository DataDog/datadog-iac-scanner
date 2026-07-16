/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package platform defines IaC scan platforms and shared rule libraries.
package platform

import (
	"slices"
	"strings"
)

// ID is the canonical all-lowercase identifier for an IaC scan platform.
type ID string

// Canonical scan-platform IDs.
const (
	Terraform               ID = "terraform"
	CloudFormation          ID = "cloudformation"
	Kubernetes              ID = "kubernetes"
	Ansible                 ID = "ansible"
	CICD                    ID = "cicd"
	Dockerfile              ID = "dockerfile"
	Knative                 ID = "knative"
	Crossplane              ID = "crossplane"
	ServerlessFW            ID = "serverlessfw"
	AzureResourceManager    ID = "azureresourcemanager"
	OpenAPI                 ID = "openapi"
	GoogleDeploymentManager ID = "googledeploymentmanager"
	DockerCompose           ID = "dockercompose"
	Pulumi                  ID = "pulumi"
	GRPC                    ID = "grpc"
	Buildah                 ID = "buildah"
)

type definition struct {
	// Canonical is the lowercase scanner identity.
	Canonical ID
	// Aliases are additional accepted names.
	Aliases []string
	// LibraryIdentity identifies the shared Rego library.
	LibraryIdentity string
	// PayloadTargets receive documents classified as this platform.
	PayloadTargets []ID
}

var definitions = []definition{
	{
		Canonical:       Terraform,
		LibraryIdentity: "terraform",
	},
	{
		Canonical:       CloudFormation,
		Aliases:         []string{"CF"},
		LibraryIdentity: "cloudFormation",
	},
	{
		Canonical:       Kubernetes,
		Aliases:         []string{"k8s"},
		LibraryIdentity: "k8s",
	},
	{
		Canonical:       Ansible,
		LibraryIdentity: "ansible",
	},
	{
		Canonical:       CICD,
		LibraryIdentity: "cicd",
	},
	{
		Canonical:       Dockerfile,
		LibraryIdentity: "dockerfile",
	},
	{
		Canonical:       Knative,
		LibraryIdentity: "knative",
		PayloadTargets:  []ID{Knative, Kubernetes},
	},
	{
		Canonical:       Crossplane,
		LibraryIdentity: "crossplane",
	},
	{
		Canonical:       ServerlessFW,
		LibraryIdentity: "serverlessFW",
		PayloadTargets:  []ID{ServerlessFW, CloudFormation},
	},
	{
		Canonical:       AzureResourceManager,
		Aliases:         []string{"bicep"},
		LibraryIdentity: "azureResourceManager",
	},
	{
		Canonical:       OpenAPI,
		LibraryIdentity: "openAPI",
	},
	{
		Canonical:       GoogleDeploymentManager,
		LibraryIdentity: "googleDeploymentManager",
	},
	{
		Canonical:       DockerCompose,
		LibraryIdentity: "dockercompose",
	},
	{
		Canonical:       Pulumi,
		LibraryIdentity: "pulumi",
	},
	{
		Canonical:       GRPC,
		LibraryIdentity: "grpc",
	},
	{
		Canonical:       Buildah,
		LibraryIdentity: "buildah",
	},
}

var aliasIndex = buildAliasIndex()

func buildAliasIndex() map[string]*definition {
	idx := make(map[string]*definition, len(definitions)*3)
	for i := range definitions {
		idx[string(definitions[i].Canonical)] = &definitions[i]
		for _, alias := range definitions[i].Aliases {
			lower := strings.ToLower(alias)
			if _, exists := idx[lower]; !exists {
				idx[lower] = &definitions[i]
			}
		}
	}
	return idx
}

// CanonicalID returns the canonical ID for any accepted name (case-insensitive).
func CanonicalID(name string) (ID, bool) {
	if def, ok := aliasIndex[strings.ToLower(name)]; ok {
		return def.Canonical, true
	}
	return "", false
}

// LibraryIdentity returns the library file key for any accepted scan-platform or shared-library name.
func LibraryIdentity(name string) (string, bool) {
	if lib, ok := sharedLibraryIdentity(name); ok {
		return lib, true
	}
	if def, ok := aliasIndex[strings.ToLower(name)]; ok {
		return def.LibraryIdentity, true
	}
	return "", false
}

// LibraryIdentityOrUnknown returns the library identity or "unknown" when the name is not recognized.
func LibraryIdentityOrUnknown(name string) string {
	if lib, ok := LibraryIdentity(name); ok {
		return lib
	}
	return "unknown"
}

// LibraryName maps a user-facing platform name to the embedded library file name.
// Unrecognized names fall back to the lower-cased input.
func LibraryName(name string) string {
	if lib, ok := LibraryIdentity(name); ok {
		return lib
	}
	return strings.ToLower(name)
}

// CompareKey returns a stable lowercase key for comparing scan-platform names across aliases.
func CompareKey(name string) string {
	if IsCrossPlatformRule(name) {
		return RulePlatformCommon
	}
	if id, ok := CanonicalID(name); ok {
		return string(id)
	}
	return strings.ToLower(name)
}

// Matches reports whether two platform names refer to the same registered platform.
func Matches(a, b string) bool {
	return CompareKey(a) == CompareKey(b)
}

// PayloadTargets returns the canonical payload IDs for any accepted name.
// Returns nil if the name is not recognized.
func PayloadTargets(name string) []ID {
	if def, ok := aliasIndex[strings.ToLower(name)]; ok {
		if len(def.PayloadTargets) == 0 {
			return []ID{def.Canonical}
		}
		return slices.Clone(def.PayloadTargets)
	}
	return nil
}
