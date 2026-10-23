/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

// Converting instances on several workers yields the documents one worker
// does, unresolved values rendered from their source included.
func TestInstantiatedDocs_ParallelConversionMatchesSerial(t *testing.T) {
	root := t.TempDir()
	modFile := writeFile(t, filepath.Join(root, "modules", "m"), "main.tf", `
variable "name" {}
variable "unknown" {}
resource "aws_s3_bucket" "b" {
  for_each = toset(["a", "b", "c"])
  bucket   = "${var.name}-${each.key}"
  policy   = var.unknown
  dynamic "cors_rule" {
    for_each = range(3)
    content {
      allowed_origins = ["${cors_rule.value}-${var.unknown}"]
    }
  }
}
data "aws_iam_policy_document" "d" {
  count = 2
  statement {
    actions = ["s3:${count.index}"]
  }
}
`)
	rootFile := writeFile(t, filepath.Join(root, "stack"), "main.tf", `
module "m" {
  source = "../modules/m"
  count  = 40
  name   = "n${count.index}"
}
`)
	files := model.FileMetadatas{fileMeta("mod", modFile), fileMeta("root", rootFile)}
	resolve := func(threshold int) string {
		previous := parallelInstanceConversion
		parallelInstanceConversion = threshold
		defer func() { parallelInstanceConversion = previous }()
		res := resolveModuleDocuments(context.Background(), files, root, nil, nil, nil, nil, nil, nil)
		require.True(t, res.ok)
		require.Len(t, res.docs, 40*3)
		out, err := json.Marshal(struct {
			Docs       []model.Document
			Suppressed instantiatedIndex
		}{res.docs, res.suppressed})
		require.NoError(t, err)
		return string(out)
	}
	require.Equal(t, resolve(1<<30), resolve(10))
}
