/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	terraformParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	scanUtils "github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

const aclRule = `package datadog

DatadogPolicy contains result if {
	some name, i
	bucket := input.document[i].resource.aws_s3_bucket[name]
	bucket.acl == "public-read"

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s].acl", [name]),
	}
}
`

func parseTerraform(t *testing.T, path string) model.FileMetadatas {
	t.Helper()
	content, err := os.ReadFile(filepath.Clean(path))
	require.NoError(t, err)

	_, docs, ignore, resolved, err := terraformParser.NewDefault().Parse(context.Background(), content, path, true, 15)
	require.NoError(t, err)

	var out model.FileMetadatas
	for _, doc := range docs {
		out = append(out, &model.FileMetadata{
			ID:                uuid.NewString(),
			ScanID:            "test",
			Document:          doc,
			LineInfoDocument:  doc,
			OriginalData:      string(content),
			Kind:              model.KindTerraform,
			FilePath:          path,
			LinesIgnore:       ignore,
			ResolvedFiles:     resolved,
			LinesOriginalData: scanUtils.SplitLines(string(content)),
		})
	}
	return out
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}
