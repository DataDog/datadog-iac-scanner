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

type fileType struct {
	dockerfile bool
}

// supportedFileTypes is the scanner's routing registry. Dockerfile filename
// candidates must not take precedence over another registered format.
var supportedFileTypes = map[string]fileType{
	".yml":               {},
	".yaml":              {},
	".json":              {},
	".sh":                {},
	".dockerfile":        {dockerfile: true},
	"Dockerfile":         {dockerfile: true},
	"possibleDockerfile": {dockerfile: true},
	".debian":            {dockerfile: true},
	".ubi8":              {dockerfile: true},
	tfpath.ExtTF:         {},
	tfpath.ExtTofu:       {},
	tfpath.ExtTFJSON:     {},
	tfpath.ExtTofuJSON:   {},
	tfpath.ExtTFVars:     {},
	".proto":             {},
	".cfg":               {},
	".conf":              {},
	".ini":               {},
	".bicep":             {},
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
