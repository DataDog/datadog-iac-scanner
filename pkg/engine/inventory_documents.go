/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/inventory"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/occurrence"
)

// documentOccurrenceIndex belongs to one Inspect call. It is only allocated
// for inventory scans and becomes read-only before query decoding starts.
type documentOccurrenceIndex map[string][]*model.ResourceOccurrence

// inventoryDocuments indexes parsed non-Terraform occurrences before anything
// rewrites or releases the documents. A panic fails the inventory.
func (c *Inspector) inventoryDocuments(ctx context.Context, files model.FileMetadatas) (index documentOccurrenceIndex) {
	if c.inventory == nil {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			contextLogger := logger.FromContext(ctx)
			contextLogger.Error().Interface("panic", r).Msg("inventory: recovered from panic while listing documents")
			c.inventory.Fail(inventory.FailureDocumentsPanic)
		}
	}()
	index = make(documentOccurrenceIndex)
	occurrence.Documents(ctx, files, func(file *model.FileMetadata, resource *model.ResourceOccurrence) {
		index[file.ID] = append(index[file.ID], resource)
		row := inventory.ProjectResource(resource)
		c.inventory.AddResource(&row)
	})
	return index
}
