/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package scan

import (
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
)

// Contract rules build their input from source, so their initial HCL parse
// only needs source metadata. Exports and any document-reading rule retain
// full preparation; lazy line-info reparses also retain their full parser.
func terraformPreparationContext(ctx context.Context, params *Parameters, queries []model.QueryMetadata) context.Context {
	if params.PayloadPath != "" || params.LineInfoPayload || len(queries) == 0 {
		return ctx
	}
	for i := range queries {
		if !engine.UsesTerraformContract(&queries[i]) {
			return ctx
		}
	}
	return parser.WithTerraformMetadataOnly(ctx)
}
