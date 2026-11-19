/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package parser

import (
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/parsecontext"
)

// WithTerraformMetadataOnly marks a Terraform parse that needs source metadata
// and syntax diagnostics but not the legacy document conversion.
func WithTerraformMetadataOnly(ctx context.Context) context.Context {
	return parsecontext.WithTerraformMetadataOnly(ctx)
}

// IsTerraformMetadataOnly reports whether ctx was marked with
// WithTerraformMetadataOnly.
func IsTerraformMetadataOnly(ctx context.Context) bool {
	return parsecontext.IsTerraformMetadataOnly(ctx)
}
