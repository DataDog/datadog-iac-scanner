/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resourceindex

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFilterByDocumentIDs(t *testing.T) {
	selectedEntry := filterTestEntry("selected")
	otherEntry := filterTestEntry("other")
	index := map[string]interface{}{
		"aws_s3_bucket": map[string]interface{}{
			"selected#[\"resource\",\"aws_s3_bucket\",\"same\"]#2": selectedEntry,
			"other#[\"resource\",\"aws_s3_bucket\",\"same\"]":      otherEntry,
		},
		"Pod": map[string]interface{}{
			"other#[]": otherEntry,
		},
	}
	lookup := filterTestLookup("selected", "other")

	filtered, filteredLookup := FilterByDocumentIDs(index, lookup, map[string]struct{}{"selected": {}})

	require.Equal(t, map[string]interface{}{
		"aws_s3_bucket": map[string]interface{}{
			"selected#[\"resource\",\"aws_s3_bucket\",\"same\"]#2": selectedEntry,
		},
	}, filtered)
	require.Equal(t, map[string]ResourceMetadata{"selected-resource": {DocumentID: "selected"}}, filteredLookup)
}

func TestFilterByDocumentIDsShallowCopiesBuckets(t *testing.T) {
	entry := filterTestEntry("selected")
	originalBucket := map[string]interface{}{"internal-key": entry}
	index := map[string]interface{}{"resource-type": originalBucket}

	filtered, _ := FilterByDocumentIDs(index, filterTestLookup("selected"), map[string]struct{}{"selected": {}})
	filteredBucket := filtered["resource-type"].(map[string]interface{})

	filteredBucket["new-key"] = filterTestEntry("selected")
	require.NotContains(t, originalBucket, "new-key")

	entry["shared"] = true
	require.Equal(t, true, filteredBucket["internal-key"].(map[string]interface{})["shared"])
}

func TestFilterByDocumentIDsRequiresDocumentIDMetadata(t *testing.T) {
	index := map[string]interface{}{
		"resource-type": map[string]interface{}{
			"scope-only": map[string]interface{}{
				EntryDD: map[string]interface{}{EntryDDScope: "selected"},
			},
			"top-level-id": map[string]interface{}{
				"documentId": "selected",
				EntryDD:      map[string]interface{}{},
			},
			"wrong-type": map[string]interface{}{
				EntryDD: map[string]interface{}{EntryDDDocumentID: 42},
			},
			"missing-dd": map[string]interface{}{},
			"not-entry":  "value",
		},
		"not-bucket": "value",
	}

	filtered, _ := FilterByDocumentIDs(index, nil, map[string]struct{}{"selected": {}})

	require.NotNil(t, filtered)
	require.Empty(t, filtered)
}

func TestFilterByDocumentIDsEmptySelection(t *testing.T) {
	filtered, _ := FilterByDocumentIDs(
		map[string]interface{}{
			"resource-type": map[string]interface{}{"key": filterTestEntry("document")},
		},
		nil,
		nil,
	)

	require.NotNil(t, filtered)
	require.Empty(t, filtered)
}

func filterTestEntry(documentID string) map[string]interface{} {
	return map[string]interface{}{
		EntryResourceType: "resource-type",
		EntryDD: map[string]interface{}{
			EntryDDID: documentID + "-resource",
		},
	}
}

func filterTestLookup(documentIDs ...string) map[string]ResourceMetadata {
	lookup := make(map[string]ResourceMetadata, len(documentIDs))
	for _, documentID := range documentIDs {
		lookup[documentID+"-resource"] = ResourceMetadata{DocumentID: documentID}
	}
	return lookup
}
