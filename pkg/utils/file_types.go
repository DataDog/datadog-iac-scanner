/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package utils

import (
	"sort"

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
	dockerfile   bool
	contentCheck ContentCheck
}

// supportedFileTypes is the scanner's routing registry. Dockerfile filename
// candidates must not take precedence over another registered format.
var supportedFileTypes = map[string]fileType{
	".yml":             {contentCheck: YAMLContent},
	".yaml":            {contentCheck: YAMLContent},
	".json":            {contentCheck: PlatformContent},
	".sh":              {contentCheck: PlatformContent},
	".dockerfile":      {dockerfile: true},
	"Dockerfile":       {dockerfile: true},
	PossibleDockerfile: {dockerfile: true, contentCheck: DockerfileContent},
	".debian":          {dockerfile: true, contentCheck: DockerfileContent},
	".ubi8":            {dockerfile: true, contentCheck: DockerfileContent},
	tfpath.ExtTF:       {},
	tfpath.ExtTofu:     {},
	tfpath.ExtTFJSON:   {},
	tfpath.ExtTofuJSON: {},
	tfpath.ExtTFVars:   {},
	".proto":           {},
	".cfg":             {contentCheck: AnsibleConfigContent},
	".conf":            {contentCheck: AnsibleConfigContent},
	".ini":             {contentCheck: AnsibleInventoryContent},
	".bicep":           {},
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
