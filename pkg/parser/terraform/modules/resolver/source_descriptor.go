/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"net/url"
	"path/filepath"
	"strings"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

type SourceDescriptor struct {
	NormalizedSource string
	SourceType       string
	SourceCategory   string
	RegistryScope    string
	RequestedVersion string
	RequestedRef     string
	Subdirectory     string
}

func DescribeModuleSource(source, version string) SourceDescriptor {
	source = strings.TrimSpace(source)
	version = strings.TrimSpace(version)
	sourceType, registryScope := tfmodules.DetectModuleSourceType(source)
	descriptor := SourceDescriptor{
		NormalizedSource: source,
		SourceType:       sourceType,
		SourceCategory:   sourceType,
		RegistryScope:    registryScope,
		RequestedVersion: version,
	}

	if address, err := tfmodules.ParseRegistryModuleSource(source); err == nil {
		address.Subdir, descriptor.Subdirectory = "", filepath.ToSlash(address.Subdir)
		descriptor.NormalizedSource = address.String()
		descriptor.SourceCategory = registryScope + "_registry"
		return descriptor
	}
	if repoURL, subdir, ref, ok := parseGitGetterSource(source); ok {
		descriptor.NormalizedSource = normalizeGitRepoURL(repoURL)
		descriptor.SourceType = sourceTypeGit
		descriptor.SourceCategory = sourceTypeGit
		descriptor.RequestedRef = ref
		descriptor.Subdirectory = filepath.ToSlash(subdir)
		return descriptor
	}

	getterSource := source
	getterType := ""
	if index := strings.Index(getterSource, "::"); index >= 0 {
		getterType = strings.ToLower(getterSource[:index])
		getterSource = getterSource[index+2:]
	}
	parsed, err := url.Parse(getterSource)
	if err != nil || parsed.Scheme == "" {
		return descriptor
	}
	descriptor.SourceType = strings.ToLower(parsed.Scheme)
	if getterType != "" {
		descriptor.SourceType = getterType
	}
	descriptor.SourceCategory = descriptor.SourceType
	descriptor.RequestedRef = parsed.Query().Get("ref")
	parsed.RawQuery = ""
	if index := strings.Index(parsed.Path, "//"); index >= 0 {
		descriptor.Subdirectory = filepath.ToSlash(parsed.Path[index+2:])
		parsed.Path = parsed.Path[:index]
	}
	parsed.Host = strings.ToLower(parsed.Host)
	descriptor.NormalizedSource = parsed.String()
	return descriptor
}
