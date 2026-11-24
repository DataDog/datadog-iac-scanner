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

// inventoryDocuments reports the resources of the parsed documents of every
// platform but Terraform. It runs before anything rewrites or releases the
// documents. A panic fails the inventory rather than the scan.
func (c *Inspector) inventoryDocuments(ctx context.Context, files model.FileMetadatas) {
	if c.inventory == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			contextLogger := logger.FromContext(ctx)
			contextLogger.Error().Interface("panic", r).Msg("inventory: recovered from panic while listing documents")
			c.inventory.Fail(inventory.FailureDocumentsPanic)
		}
	}()
	occurrence.Documents(ctx, files, func(file *model.FileMetadata, resource *model.ResourceOccurrence) {
		file.ResourceOccurrences = append(file.ResourceOccurrences, resource)
		row := inventory.ProjectResource(resource)
		c.inventory.AddResource(&row)
	})
}
