/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package capture

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readGolden(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "golden.json"))
	require.NoError(t, err)
	// A Windows checkout may convert the file to CRLF line endings.
	return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
}

// TestGoldenRoundTrip locks the format: the golden document decodes with no
// unknown field and encodes back to the same bytes.
func TestGoldenRoundTrip(t *testing.T) {
	golden := readGolden(t)

	dec := json.NewDecoder(bytes.NewReader(golden))
	dec.DisallowUnknownFields()
	var doc Document
	require.NoError(t, dec.Decode(&doc))

	out, err := json.MarshalIndent(doc, "", "  ")
	require.NoError(t, err)
	assert.Equal(t, string(bytes.TrimSpace(golden)), string(out))
}

// TestGoldenContent checks the properties of the format that consumers rely on.
func TestGoldenContent(t *testing.T) {
	var doc Document
	require.NoError(t, json.Unmarshal(readGolden(t), &doc))

	assert.Equal(t, FormatVersion, doc.FormatVersion)
	assert.Equal(t, StatusEvaluated, doc.Result.Status)
	assert.True(t, doc.Result.Partial, "placeholders make the evaluation partial")
	assert.Equal(t, []string{"demo:dbName"}, doc.Config.Placeholders)

	byName := map[string]Resource{}
	for _, r := range doc.Resources {
		byName[r.Type+"::"+r.Name] = r
	}

	db := byName["aws:rds/instance:Instance::db"]
	assert.Equal(t, map[string]any{MarkerSecret: true}, db.Inputs["password"])
	require.NotNil(t, db.Source)
	assert.Equal(t, "infra/__main__.py", db.Source.Path)
	assert.Equal(t, 26, db.Source.Line)

	component := byName["demo:index:Assets::assets"]
	assert.False(t, component.Custom)

	bucket := byName["aws:s3/bucketV2:BucketV2::assets"]
	assert.Equal(t, component.URN, bucket.Parent)
	assert.Contains(t, bucket.URN, "demo:index:Assets$aws:s3/bucketV2:BucketV2", "child URNs carry the parent type chain")

	pab := byName["aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock::assets-pab"]
	assert.Equal(t, map[string]any{MarkerUnknown: true}, pab.Inputs["bucket"])
	assert.Equal(t, []string{bucket.URN}, pab.PropertyDependencies["bucket"])

	fn := byName["aws:lambda/function:Function::handler"]
	assert.Equal(t, map[string]any{MarkerResourceRef: "urn:pulumi:prod::demo::aws:iam/role:Role::handler-role"}, fn.Inputs["role"])
	require.NotNil(t, fn.Source)
	assert.Empty(t, fn.Source.Path, "a position outside the scan root has no path")
	assert.Zero(t, fn.Source.Line)

	require.Len(t, doc.Invokes, 1)
	assert.True(t, doc.Invokes[0].Placeholder)
	require.Len(t, doc.Reads, 1)
	assert.Equal(t, "pulumi:pulumi:StackReference", doc.Reads[0].Type)
}
