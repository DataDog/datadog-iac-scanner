/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
)

// PathSegment addresses exactly one object key or array index. Numeric-looking
// keys remain keys; they are never interpreted as array indexes.
type PathSegment struct {
	Key     string
	Index   int
	IsIndex bool
}

// SourcePath is relative to the parsed document identified by a finding.
type SourcePath []PathSegment

// SourcePathIdentity provides a stable identity and an unambiguous display key.
// The display key is never parsed back for source lookup.
func SourcePathIdentity(path SourcePath, documentIndex int) (id, display string) {
	parts := make([]interface{}, 0, len(path))
	for _, segment := range path {
		if segment.IsIndex {
			parts = append(parts, segment.Index)
		} else {
			parts = append(parts, segment.Key)
		}
	}
	raw, _ := json.Marshal(parts) // Only strings and integers are encoded.
	digest := sha256.Sum256([]byte(strconv.Itoa(documentIndex) + ":" + string(raw)))
	return "source-v1:" + hex.EncodeToString(digest[:]), string(raw)
}
