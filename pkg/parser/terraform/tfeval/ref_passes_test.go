/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

func TestResourceSelfReferenceDetection(t *testing.T) {
	tests := []struct {
		name                      string
		src                       string
		wantLocals, wantResources bool
	}{
		{
			name: "inputs only",
			src: `
locals { name = "${var.prefix}-bucket" }
resource "aws_s3_bucket" "b" { bucket = local.name }`,
		},
		{
			name: "data sources and undeclared types are not the module's resources",
			src: `
resource "aws_s3_bucket_policy" "p" {
  bucket = data.aws_s3_bucket.existing.id
  policy = aws_iam_policy_document.doc.json
}`,
		},
		{
			name: "attribute reads a sibling resource",
			src: `
resource "aws_s3_bucket" "b" {}
resource "aws_s3_bucket_policy" "p" { bucket = aws_s3_bucket.b.id }`,
			wantResources: true,
		},
		{
			name: "nested dynamic block reads a sibling resource",
			src: `
resource "aws_s3_bucket" "b" {}
resource "aws_s3_bucket_lifecycle_configuration" "l" {
  dynamic "rule" {
    for_each = var.rules
    content { id = "${aws_s3_bucket.b.id}-${rule.key}" }
  }
}`,
			wantResources: true,
		},
		{
			name: "for expression reads a sibling resource",
			src: `
resource "aws_subnet" "s" { count = 2 }
resource "aws_route_table_association" "a" { subnet_ids = [for s in aws_subnet.s : s.id] }`,
			wantResources: true,
		},
		{
			name: "local reads a resource",
			src: `
locals { bucket_arn = aws_s3_bucket.b.arn }
resource "aws_s3_bucket" "b" {}`,
			wantLocals: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, diags := hclsyntax.ParseConfig([]byte(tt.src), "main.tf", hcl.Pos{Line: 1, Column: 1})
			if diags.HasErrors() {
				t.Fatalf("parse: %v", diags)
			}
			_, localExprs, _, resourceBlocks, _ := collectBlocks([]*hclsyntax.Body{file.Body.(*hclsyntax.Body)})
			types := declaredResourceTypes(resourceBlocks)
			if got := localsReadResources(localExprs, types); got != tt.wantLocals {
				t.Errorf("localsReadResources = %v, want %v", got, tt.wantLocals)
			}
			if got := resourcesReadResources(resourceBlocks, types); got != tt.wantResources {
				t.Errorf("resourcesReadResources = %v, want %v", got, tt.wantResources)
			}
		})
	}
}
