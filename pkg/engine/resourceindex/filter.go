/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resourceindex

func FilterByDocumentIDs(
	index map[string]interface{},
	lookup map[string]ResourceMetadata,
	documentIDs map[string]struct{},
) (filtered map[string]interface{}, filteredLookup map[string]ResourceMetadata) {
	filtered = make(map[string]interface{})
	filteredLookup = make(map[string]ResourceMetadata)
	for resourceType, rawBucket := range index {
		bucket, ok := rawBucket.(map[string]interface{})
		if !ok {
			continue
		}

		filteredBucket := make(map[string]interface{})
		for internalKey, rawEntry := range bucket {
			entry, ok := rawEntry.(map[string]interface{})
			if !ok {
				continue
			}
			metadata, ok := entry[EntryDD].(map[string]interface{})
			if !ok {
				continue
			}
			resourceID, ok := metadata[EntryDDID].(string)
			if !ok {
				continue
			}
			resourceMetadata, ok := lookup[resourceID]
			if !ok {
				continue
			}
			if _, selected := documentIDs[resourceMetadata.DocumentID]; selected {
				filteredBucket[internalKey] = rawEntry
				filteredLookup[resourceID] = resourceMetadata
			}
		}
		if len(filteredBucket) > 0 {
			filtered[resourceType] = filteredBucket
		}
	}
	return filtered, filteredLookup
}
