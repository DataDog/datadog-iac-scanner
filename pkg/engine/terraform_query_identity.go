/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// A query name can be the same basename in different provider directories.
// Scheduling and gate lookup must use the rule identity, not its display name.
func terraformQueryKey(query *model.QueryMetadata) string {
	if id, ok := query.Metadata["id"].(string); ok && id != "" && id != DefaultQueryID {
		return "id:" + id
	}
	// Internal callers can omit metadata IDs. Keep different source rules
	// separate there too, including rules that have different input data.
	source := strings.Join([]string{query.Platform, query.Query, query.Content, query.InputData}, "\x00")
	digest := sha256.Sum256([]byte(source))
	return "source:" + hex.EncodeToString(digest[:])
}
