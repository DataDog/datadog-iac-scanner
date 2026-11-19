/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"encoding/json"
)

// PathSegment addresses exactly one object key or array index. Numeric-looking
// keys remain keys; they are never interpreted as array indexes.
type PathSegment struct {
	Key     string
	Index   int
	IsIndex bool
}

// SourcePath addresses written syntax within a finding's source document.
// Normalized or generated semantic views require an explicit source adapter.
type SourcePath []PathSegment

// DisplayKey formats an unambiguous source location for display only.
// It is never parsed back for source lookup or used as a finding identity.
func (path SourcePath) DisplayKey() string {
	parts := make([]interface{}, 0, len(path))
	for _, segment := range path {
		if segment.IsIndex {
			parts = append(parts, segment.Index)
		} else {
			parts = append(parts, segment.Key)
		}
	}
	raw, _ := json.Marshal(parts) // Only strings and integers are encoded.
	return string(raw)
}
