/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

const referenceCommonLib = `package generic.common

import rego.v1

finding(subject, path, details) := object.union(details, {"_dd_id": subject._dd_meta.id, "path": path})

is_list(v) if is_array(v)
`

const referenceTerraformLib = `package generic.terraform

import rego.v1

import data.generic.common

_dd := object.get(input, "_dd", {})

_placeholder := object.get(_dd, "placeholder", "\u0000dd-unknown")

blocks(type) := object.get(_dd, ["blocks", "resource", type], [])

by_id(id) := object.get(_dd, ["by_id", id], _placeholder)

_nested(block) := object.get(object.get(_dd, "nested", {}), object.get(block._dd_meta, "id", ""), {})

nested(block, name) := list if {
	list := object.get(_nested(block), name, null)
	common.is_list(list)
} else := list if {
	list := block[name]
	common.is_list(list)
} else := [_placeholder] if {
	block[name] == _placeholder
} else := []

related(block, type, path) := [by_id(id) | some id in object.get(_dd, ["related", block._dd_meta.id, type, path], [])]

literal_keys := {"aws_s3_bucket_versioning": {"bucket": {"aws_s3_bucket": ["bucket"]}}}
`

const referenceBucketRule = `package datadog

import rego.v1

import data.generic.common as common
import data.generic.terraform as tf

DatadogPolicy contains result if {
	some b in tf.blocks("aws_s3_bucket")
	result := common.finding(b, ["bucket"], {})
}
`

const referenceVersioningRule = `package datadog

import rego.v1

import data.generic.common as common
import data.generic.terraform as tf

DatadogPolicy contains result if {
	some b in tf.blocks("aws_s3_bucket")
	not versioned(b)
	result := common.finding(b, [], {})
}

versioned(b) if {
	some v in tf.related(b, "aws_s3_bucket_versioning", "bucket")
	some c in tf.nested(v, "versioning_configuration")
	c.status == "Enabled"
}
`

type referenceQueriesSource struct {
	queries []model.QueryMetadata
}

func (s *referenceQueriesSource) GetQueries(_ context.Context, _ *source.QueryInspectorParameters) ([]model.QueryMetadata, error) {
	return s.queries, nil
}

func (s *referenceQueriesSource) GetQueryLibrary(_ context.Context, platform string) (source.RegoLibraries, error) {
	switch platform {
	case "common":
		return source.RegoLibraries{LibraryCode: referenceCommonLib, LibraryInputData: "{}"}, nil
	case "terraform":
		return source.RegoLibraries{LibraryCode: referenceTerraformLib, LibraryInputData: "{}"}, nil
	default:
		return source.RegoLibraries{LibraryCode: "package generic." + platform + "\n", LibraryInputData: "{}"}, nil
	}
}

func referenceQuery(name, id, content string) model.QueryMetadata {
	return model.QueryMetadata{
		Query: name, Content: content, InputData: "{}", Platform: "terraform",
		Metadata: map[string]interface{}{"id": id, "platform": "Terraform", "queryName": name, "severity": "MEDIUM"},
	}
}

// referenceFixture writes two identical envs sharing a module (digest/fanout),
// one distinct env, and a cross-root companion layout like the e2e cross-root
// fixture (ops versions prod; examples/ must not).
func referenceFixture(t *testing.T) (dir string, files model.FileMetadatas) {
	t.Helper()
	dir = t.TempDir()
	modDir := filepath.Join(dir, "modules", "svc")
	require.NoError(t, os.MkdirAll(modDir, 0o755))
	modPath := writeFile(t, modDir, "main.tf", `
variable "name" {}
resource "aws_s3_bucket" "b" { bucket = var.name }
`)
	files = append(files, parseTerraform(t, modPath)...)

	for _, env := range []struct{ name, bucket string }{
		{"a", "shared"},
		{"b", "shared"},
		{"c", "other"},
	} {
		rootDir := filepath.Join(dir, "envs", env.name)
		require.NoError(t, os.MkdirAll(rootDir, 0o755))
		path := writeFile(t, rootDir, "main.tf", fmt.Sprintf(`
module "svc" {
  source = "../../modules/svc"
  name   = %q
}
`, env.bucket))
		files = append(files, parseTerraform(t, path)...)
	}

	prod := writeFile(t, filepath.Join(dir, "prod"), "main.tf", `
resource "aws_s3_bucket" "versioned_elsewhere" {
  bucket = "acme-versioned-elsewhere"
}
resource "aws_s3_bucket" "planted_in_example" {
  bucket = "acme-planted-in-example"
}
`)
	ops := writeFile(t, filepath.Join(dir, "ops"), "main.tf", `
resource "aws_s3_bucket_versioning" "prod" {
  bucket = "acme-versioned-elsewhere"
  versioning_configuration {
    status = "Enabled"
  }
}
`)
	example := writeFile(t, filepath.Join(dir, "examples", "demo"), "main.tf", `
resource "aws_s3_bucket_versioning" "planted" {
  bucket = "acme-planted-in-example"
  versioning_configuration {
    status = "Enabled"
  }
}
`)
	files = append(files, parseTerraform(t, prod)...)
	files = append(files, parseTerraform(t, ops)...)
	files = append(files, parseTerraform(t, example)...)
	return dir, files
}

func scanReferenceMode(t *testing.T, dir string, files model.FileMetadatas, reference bool) []model.Vulnerability {
	t.Helper()
	ins := newTestInspector(t, inspectorOpts{
		querySource: &referenceQueriesSource{queries: []model.QueryMetadata{
			referenceQuery("every_bucket", "every-bucket", referenceBucketRule),
			referenceQuery("bucket_without_versioning", "no-versioning", referenceVersioningRule),
		}},
		repoPath:      dir,
		vb:            DefaultVulnerabilityBuilder,
		tracker:       &tracker.CITracker{},
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	ins.SetTerraformReferenceMode(reference)
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	return vulns
}

type findingKey struct {
	QueryID, File, ResourceType, ResourceName, SearchKey string
	Line                                                 int
}

func findingKeys(vulns []model.Vulnerability) []findingKey {
	out := make([]findingKey, len(vulns))
	for i := range vulns {
		out[i] = findingKey{
			QueryID: vulns[i].QueryID, File: filepath.ToSlash(vulns[i].FileName),
			ResourceType: vulns[i].ResourceType, ResourceName: vulns[i].ResourceName,
			SearchKey: vulns[i].SearchKey, Line: vulns[i].Line,
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.QueryID != b.QueryID {
			return a.QueryID < b.QueryID
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.ResourceName != b.ResourceName {
			return a.ResourceName < b.ResourceName
		}
		if a.SearchKey != b.SearchKey {
			return a.SearchKey < b.SearchKey
		}
		return a.Line < b.Line
	})
	return out
}

// Optimized chunking/merge/dedup/fanout and per-root reference evaluation
// report the same findings on a multi-root fixture with shared modules and
// cross-root literal companions.
func TestTerraformReferenceModeMatchesOptimized(t *testing.T) {
	dir, files := referenceFixture(t)
	optimized := findingKeys(scanReferenceMode(t, dir, files, false))
	reference := findingKeys(scanReferenceMode(t, dir, files, true))
	require.NotEmpty(t, optimized)
	require.Equal(t, optimized, reference)

	var planted, versionedElsewhere bool
	for _, k := range optimized {
		if k.QueryID != "no-versioning" {
			continue
		}
		switch k.ResourceName {
		case "planted_in_example":
			planted = true
			require.Contains(t, k.File, "/prod/")
		case "versioned_elsewhere":
			versionedElsewhere = true
		}
	}
	require.True(t, planted, "examples/ companions must not clear the planted bucket")
	require.False(t, versionedElsewhere, "ops companion must clear the versioned bucket")
}
