/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package utils

import (
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
)

// PossibleDockerfile is the routing token for Dockerfile.<name> candidates.
const PossibleDockerfile = "possibleDockerfile"

// ContentCheck identifies the content policy used by disk and pushed scans.
type ContentCheck uint8

const (
	// NoContentCheck routes unambiguous types by filename alone.
	NoContentCheck ContentCheck = iota
	// DockerfileContent requires an initial FROM after optional ARGs.
	DockerfileContent
	// AnsibleConfigContent requires Ansible configuration sections.
	AnsibleConfigContent
	// AnsibleInventoryContent requires Ansible inventory sections.
	AnsibleInventoryContent
	// YAMLContent excludes catalogs and selects a platform from YAML content.
	YAMLContent
	// PlatformContent selects a platform from JSON or shell content.
	PlatformContent
)

type fileType struct {
	dockerfile      bool
	contentCheck    ContentCheck
	platform        string
	caseInsensitive bool
	pattern         string
}

// supportedFileTypes is the scanner's routing registry. Dockerfile filename
// candidates must not take precedence over another registered format.
var supportedFileTypes = map[string]fileType{
	".yml":        {contentCheck: YAMLContent},
	".yaml":       {contentCheck: YAMLContent},
	".json":       {contentCheck: PlatformContent},
	".sh":         {contentCheck: PlatformContent},
	".dockerfile": {dockerfile: true, platform: "dockerfile", caseInsensitive: true},
	"Dockerfile":  {dockerfile: true, platform: "dockerfile", caseInsensitive: true},
	PossibleDockerfile: {
		dockerfile: true, platform: "dockerfile", contentCheck: DockerfileContent,
		caseInsensitive: true, pattern: "Dockerfile.*",
	},
	".debian":          {dockerfile: true, platform: "dockerfile", contentCheck: DockerfileContent},
	".ubi8":            {dockerfile: true, platform: "dockerfile", contentCheck: DockerfileContent},
	tfpath.ExtTF:       {platform: "terraform"},
	tfpath.ExtTofu:     {platform: "terraform"},
	tfpath.ExtTFJSON:   {platform: "terraform", caseInsensitive: true},
	tfpath.ExtTofuJSON: {platform: "terraform", caseInsensitive: true},
	tfpath.ExtTFVars:   {platform: "terraform"},
	".proto":           {platform: "grpc"},
	".cfg":             {contentCheck: AnsibleConfigContent},
	".conf":            {contentCheck: AnsibleConfigContent},
	".ini":             {contentCheck: AnsibleInventoryContent},
	".bicep":           {platform: "bicep"},
}

// SupportedFileTypes returns the sorted extension and filename tokens routed
// by the scanner. The returned slice is independent of the registry.
func SupportedFileTypes() []string {
	types := make([]string, 0, len(supportedFileTypes))
	for token := range supportedFileTypes {
		types = append(types, token)
	}
	sort.Strings(types)
	return types
}

// IsSupportedFileType reports whether the scanner routes this extension token.
func IsSupportedFileType(token string) bool {
	_, ok := supportedFileTypes[token]
	return ok
}

// ContentCheckForFileType returns the registered content policy for a token.
func ContentCheckForFileType(token string) ContentCheck {
	return supportedFileTypes[token].contentCheck
}

// NeedsContentCheck reports whether routing this token requires file bytes.
func NeedsContentCheck(token string) bool {
	return ContentCheckForFileType(token) != NoContentCheck
}

// PlatformForFileType returns the fixed platform, or empty for content-selected types.
func PlatformForFileType(token string) string { return supportedFileTypes[token].platform }

// FilePattern describes filename matching independently of IDE resolution strategy.
type FilePattern struct {
	Token            string
	Pattern          string
	CaseSensitive    bool
	ExcludedSuffixes []string
}

// FilePatterns derives the IDE filename rules from the scanner's routing registry.
func FilePatterns() []FilePattern {
	patterns := make([]FilePattern, 0, len(supportedFileTypes))
	for _, token := range SupportedFileTypes() {
		format := supportedFileTypes[token]
		pattern := format.pattern
		if pattern == "" {
			pattern = token
		}
		rule := FilePattern{Token: token, Pattern: pattern, CaseSensitive: !format.caseInsensitive}
		if token == PossibleDockerfile {
			// Reserve registered non-Dockerfile suffixes even in a different case;
			// that must not implicitly enable uppercase extensions for other formats.
			for suffix, other := range supportedFileTypes {
				if !other.dockerfile && strings.HasPrefix(suffix, ".") {
					rule.ExcludedSuffixes = append(rule.ExcludedSuffixes, suffix)
				}
			}
			rule.ExcludedSuffixes = append(rule.ExcludedSuffixes, dockerfileAuxiliarySuffixes...)
			sort.Strings(rule.ExcludedSuffixes)
		}
		patterns = append(patterns, rule)
	}
	return patterns
}
