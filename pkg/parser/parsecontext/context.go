/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package parsecontext

import "context"

type lineInfoOnlyKey struct{}
type terraformMetadataOnlyKey struct{}

// WithLineInfoOnly marks a parse that only needs document line metadata.
func WithLineInfoOnly(ctx context.Context) context.Context {
	return context.WithValue(ctx, lineInfoOnlyKey{}, true)
}

// IsLineInfoOnly reports whether ctx was marked for a line-info-only parse.
func IsLineInfoOnly(ctx context.Context) bool {
	v, _ := ctx.Value(lineInfoOnlyKey{}).(bool)
	return v
}

// WithTerraformMetadataOnly marks a Terraform parse that needs source metadata
// and syntax diagnostics but not the legacy document conversion.
func WithTerraformMetadataOnly(ctx context.Context) context.Context {
	return context.WithValue(ctx, terraformMetadataOnlyKey{}, true)
}

// IsTerraformMetadataOnly reports whether ctx was marked for metadata-only
// Terraform parsing.
func IsTerraformMetadataOnly(ctx context.Context) bool {
	v, _ := ctx.Value(terraformMetadataOnlyKey{}).(bool)
	return v
}
