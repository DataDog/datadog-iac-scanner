/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package eval

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/pulumi/capture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests below run real Pulumi programs with the real Pulumi SDKs. They are
// opt-in because the scanner never installs dependencies:
//
//	PULUMI_EVAL_TEST_PYTHON     an interpreter with testdata/real-python/requirements.txt installed
//	PULUMI_EVAL_TEST_GOMODCACHE a module cache with the modules of testdata/real-go
//	                            (go mod download in that directory)
//	PULUMI_EVAL_TEST_GO         optional, a go toolchain recent enough for testdata/real-go/go.mod

func byTypeName(doc *capture.Document) map[string]capture.Resource {
	out := map[string]capture.Resource{}
	for _, r := range doc.Resources {
		out[r.Type+"::"+r.Name] = r
	}
	return out
}

// lineOf returns the 1-based line of the first line of file that contains s.
func lineOf(t *testing.T, file, s string) int {
	t.Helper()
	b, err := os.ReadFile(file) //nolint:gosec // test fixture
	require.NoError(t, err)
	for i, l := range strings.Split(string(b), "\n") {
		if strings.Contains(l, s) {
			return i + 1
		}
	}
	t.Fatalf("%q not found in %s", s, file)
	return 0
}

func TestRealSDKPython(t *testing.T) {
	skipWithoutProcessGroups(t)
	python := os.Getenv("PULUMI_EVAL_TEST_PYTHON")
	if python == "" {
		t.Skip("set PULUMI_EVAL_TEST_PYTHON to an interpreter with testdata/real-python/requirements.txt installed")
	}
	dir := copyFixture(t, "real-python")
	doc := single(t, evaluate(t, dir, &Options{Python: python}))
	require.Equal(t, capture.StatusEvaluated, doc.Result.Status, doc.Result.Message)
	assert.Equal(t, "prod", doc.Stack)
	assert.False(t, doc.Result.Partial)
	assert.Equal(t, "true", doc.Config.Values["demo:public"])
	require.Len(t, doc.Resources, 16, "the prototype fixture declares 16 resources")

	main := filepath.Join(dir, "__main__.py")
	for _, r := range doc.Resources {
		require.NotNil(t, r.Source, r.URN)
		assert.Equal(t, "__main__.py", r.Source.Path, r.URN)
		assert.Positive(t, r.Source.Line, r.URN)
	}
	res := byTypeName(&doc)
	db := res["aws:rds/instance:Instance::db"]
	assert.Equal(t, lineOf(t, main, "db = rds.Instance("), db.Source.Line)
	assert.Equal(t, true, db.Inputs["publiclyAccessible"])
	assert.Equal(t, true, res["aws:rds/instance:Instance::db2"].Inputs["publiclyAccessible"], "read from Pulumi.prod.yaml")

	assert.False(t, res["demo:SecureBucket::assets"].Custom, "a component resource")
	assert.Equal(t, "public-read", res["aws:s3/bucketV2:BucketV2::assets"].Inputs["acl"],
		"same name as the component, a different resource: the key is the URN")

	pab := res["aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock::data-pab"]
	assert.Equal(t, map[string]any{capture.MarkerUnknown: true}, pab.Inputs["bucket"])
	assert.Equal(t, []string{res["aws:s3/bucketV2:BucketV2::data"].URN}, pab.PropertyDependencies["bucket"])

	require.Len(t, doc.Invokes, 2)
	for _, i := range doc.Invokes {
		assert.True(t, i.Placeholder, i.Token)
	}
	assert.Equal(t, []any{"amazon"}, doc.Invokes[1].Args["owners"])
}

func TestRealSDKGo(t *testing.T) {
	skipWithoutProcessGroups(t)
	modCache := os.Getenv("PULUMI_EVAL_TEST_GOMODCACHE")
	if modCache == "" {
		t.Skip("set PULUMI_EVAL_TEST_GOMODCACHE to a module cache with the modules of testdata/real-go")
	}
	gotool, gocache := goToolchain(t)
	if v := os.Getenv("PULUMI_EVAL_TEST_GO"); v != "" {
		gotool = v
	}
	dir := copyFixture(t, "real-go")
	doc := single(t, evaluate(t, dir, &Options{Go: gotool, GoModCache: modCache, GoCache: gocache, BuildTimeout: 20 * time.Minute}))
	require.Equal(t, capture.StatusEvaluated, doc.Result.Status, doc.Result.Message)
	require.Len(t, doc.Resources, 4, "the prototype fixture declares 4 resources")

	res := byTypeName(&doc)
	db := res["aws:rds/instance:Instance::db"]
	assert.Equal(t, true, db.Inputs["storageEncrypted"], "read from Pulumi.prod.yaml")
	require.NotNil(t, db.Source)
	assert.Equal(t, "main.go", db.Source.Path)
	assert.Equal(t, lineOf(t, filepath.Join(dir, "main.go"), `rds.NewInstance(ctx, "db"`), db.Source.Line)
}
