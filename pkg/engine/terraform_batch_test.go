/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

const batchPublicBucketRule = `package datadog

import rego.v1

DatadogPolicy contains result if {
	doc := input.document[i]
	some name, bucket in doc.resource.aws_s3_bucket
	bucket.acl == "public-read"
	result := {
		"documentId": doc.id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s].acl", [name]),
	}
}
`

const batchBucketWithoutPolicyRule = `package datadog

import rego.v1

has_policy(name) if {
	some d in input.document
	d.resource.aws_s3_bucket_policy[_].bucket == name
}

DatadogPolicy contains result if {
	doc := input.document[i]
	some name, _ in doc.resource.aws_s3_bucket
	not has_policy(name)
	result := {
		"documentId": doc.id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s]", [name]),
	}
}
`

// batchConflictingRule fails to evaluate on a bucket both private and tagged
// conflict: kind then has two outputs.
const batchConflictingRule = `package datadog

import rego.v1

kind(b) := "private" if b.acl == "private"

kind(b) := "conflict" if b.tags.conflict == "yes"

DatadogPolicy contains result if {
	doc := input.document[i]
	some name, bucket in doc.resource.aws_s3_bucket
	kind(bucket) == "private"
	result := {
		"documentId": doc.id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s].acl", [name]),
	}
}
`

func batchQuery(name, content string) model.QueryMetadata {
	return model.QueryMetadata{
		Query:       name,
		Content:     content,
		InputData:   "{}",
		Platform:    "terraform",
		Metadata:    map[string]interface{}{"id": name, "platform": "Terraform"},
		Aggregation: 1,
	}
}

// batchCorpus writes 3*batch+1 Terraform files, one bucket each, public on
// even files. Each policy is in a file of another batch than its bucket.
// With conflict, the file at 2*batch+2 holds a bucket batchConflictingRule
// cannot evaluate.
func batchCorpus(t *testing.T, batch int, conflict bool) []string {
	t.Helper()
	root := t.TempDir()
	n := 3*batch + 1
	policies := map[int]int{n - 1: 1, batch + 1: n - 2}
	paths := make([]string, 0, n)
	for i := range n {
		acl := "private"
		if i%2 == 0 {
			acl = "public-read"
		}
		tags := ""
		if conflict && i == 2*batch+2 {
			acl, tags = "private", "\n  tags = { conflict = \"yes\" }"
		}
		content := fmt.Sprintf("resource \"aws_s3_bucket\" \"b%02d\" {\n  acl = %q%s\n}\n", i, acl, tags)
		if of, ok := policies[i]; ok {
			content += fmt.Sprintf("\nresource \"aws_s3_bucket_policy\" \"p%02d\" {\n  bucket = \"b%02d\"\n}\n", of, of)
		}
		path := filepath.Join(root, fmt.Sprintf("f%02d.tf", i))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		paths = append(paths, path)
	}
	return paths
}

type batchScan struct {
	findings []model.Vulnerability
	failed   map[string]error
	executed int
	logs     string
}

// scanBatched scans paths with the release and compaction settings of a
// large scan, batching documents by batch.
func scanBatched(t *testing.T, paths []string, queries []model.QueryMetadata, batch, workers int,
	vb VulnerabilityBuilder) batchScan {
	t.Helper()
	defer func(saved int) { terraformBatchDocs = saved }(terraformBatchDocs)
	terraformBatchDocs = batch

	var files model.FileMetadatas
	for _, path := range paths {
		files = append(files, parseTerraform(t, path)...)
	}
	if vb == nil {
		vb = DefaultVulnerabilityBuilder
	}
	tr := &tracker.CITracker{}
	ins := newTestInspector(t, inspectorOpts{
		queries:       queries,
		repoPath:      filepath.Dir(paths[0]),
		vb:            vb,
		tracker:       tr,
		numWorkers:    workers,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	ins.SetReleaseDocumentsAfterPayload(true)
	ins.SetReleasePostEvalData(true)
	ins.SetCompactFindingsAtDecode(true)

	var logs bytes.Buffer
	ctx := zerolog.New(zerolog.SyncWriter(&logs)).WithContext(context.Background())
	vulns, err := ins.Inspect(ctx, "test", files, []string{"terraform"})
	require.NoError(t, err)
	for i := range vulns {
		vulns[i].FileID = ""
		vulns[i].QueryDuration = 0
	}
	return batchScan{findings: vulns, failed: ins.GetFailedQueries(), executed: tr.ExecutedQueries, logs: logs.String()}
}

func resourceNamesOf(vulns []model.Vulnerability, queryID string) []string {
	var names []string
	for i := range vulns {
		if vulns[i].QueryID == queryID {
			names = append(names, vulns[i].ResourceName)
		}
	}
	return names
}

func TestEvalTerraformInBatches_MatchesSinglePayload(t *testing.T) {
	const batch = 4
	paths := batchCorpus(t, batch, false)
	queries := []model.QueryMetadata{
		batchQuery("public_bucket", batchPublicBucketRule),
		batchQuery("bucket_without_policy", batchBucketWithoutPolicyRule),
	}

	single := scanBatched(t, paths, queries, len(paths), 4, nil)
	batched := scanBatched(t, paths, queries, batch, 4, nil)

	require.NotContains(t, single.logs, "in batches of")
	require.Contains(t, batched.logs, "1 document-local Terraform rules on 13 documents in batches of 4, 1 joining")
	require.Empty(t, batched.failed)
	require.NotEmpty(t, single.findings)
	require.Equal(t, single.findings, batched.findings)
	require.Len(t, resourceNamesOf(batched.findings, "public_bucket"), 7)
}

func TestEvalTerraformInBatches_JoiningRuleSeesWholeCorpus(t *testing.T) {
	const batch = 4
	paths := batchCorpus(t, batch, false)
	got := scanBatched(t, paths, []model.QueryMetadata{batchQuery("bucket_without_policy", batchBucketWithoutPolicyRule)},
		batch, 4, nil)

	flagged := resourceNamesOf(got.findings, "bucket_without_policy")
	require.Len(t, flagged, 11)
	require.NotContains(t, flagged, "b01", "its policy is in the last batch")
	require.NotContains(t, flagged, "b11", "its policy is in the second batch")
}

func TestEvalTerraformInBatches_TallyCountsEachRuleOnce(t *testing.T) {
	const batch = 4
	paths := batchCorpus(t, batch, true)
	queries := []model.QueryMetadata{
		batchQuery("public_bucket", batchPublicBucketRule),
		batchQuery("bucket_without_policy", batchBucketWithoutPolicyRule),
		batchQuery("conflicting", batchConflictingRule),
	}

	single := scanBatched(t, paths, queries, len(paths), 4, nil)
	batched := scanBatched(t, paths, queries, batch, 4, nil)

	for _, scan := range []batchScan{single, batched} {
		require.Equal(t, 2, scan.executed, "each rule that did not fail is executed once")
		require.Len(t, scan.failed, 1)
		require.Contains(t, scan.failed, "conflicting")
		require.Empty(t, resourceNamesOf(scan.findings, "conflicting"),
			"a rule that fails in one batch reports nothing, as when it fails on the whole corpus")
	}
	require.Equal(t, single.findings, batched.findings)
}

func TestEvalTerraformInBatches_BoundsJoiningRuleConcurrency(t *testing.T) {
	const batch = 4
	paths := batchCorpus(t, batch, false)
	queries := make([]model.QueryMetadata, 0, 6)
	for i := range 6 {
		queries = append(queries, batchQuery(fmt.Sprintf("bucket_without_policy_%d", i), batchBucketWithoutPolicyRule))
	}
	var mu sync.Mutex
	inFlight, peak := 0, 0
	vb := func(ctx context.Context, qCtx *QueryContext, tr Tracker, v interface{},
		d *detector.DetectLine, old bool, duration time.Duration) (*model.Vulnerability, error) {
		mu.Lock()
		inFlight++
		peak = max(peak, inFlight)
		mu.Unlock()
		time.Sleep(5 * time.Millisecond)
		mu.Lock()
		inFlight--
		mu.Unlock()
		return DefaultVulnerabilityBuilder(ctx, qCtx, tr, v, d, old, duration)
	}

	got := scanBatched(t, paths, queries, batch, 8, vb)

	require.Contains(t, got.logs, "0 document-local Terraform rules")
	require.Len(t, got.findings, 6*11)
	require.LessOrEqual(t, peak, terraformJoiningWorkers)
}

func TestBatchLargeTerraform_Gate(t *testing.T) {
	defer func(saved int) { terraformBatchDocs = saved }(terraformBatchDocs)
	terraformBatchDocs = 2
	docs := func(n int) platformPayloads {
		terms := make([]*ast.Term, n)
		for i := range terms {
			terms[i] = ast.ObjectTerm(ast.Item(ast.StringTerm("id"), ast.StringTerm(fmt.Sprint(i))))
		}
		return terraformPayloads(assembleDocumentPayload(terms))
	}
	terraformOnly := []model.QueryMetadata{{Platform: "terraform"}}
	tests := []struct {
		name     string
		queries  []model.QueryMetadata
		payloads platformPayloads
		set      func(*Inspector)
		want     bool
	}{
		{"above the batch size", terraformOnly, docs(3), func(*Inspector) {}, true},
		{"at the batch size", terraformOnly, docs(2), func(*Inspector) {}, false},
		{"coverage", terraformOnly, docs(3), func(c *Inspector) { c.EnableCoverageReport() }, false},
		{"another platform", append([]model.QueryMetadata{{Platform: "dockerfile"}}, terraformOnly...), docs(3),
			func(*Inspector) {}, false},
		{"no compaction", terraformOnly, docs(3), func(c *Inspector) { c.SetCompactFindingsAtDecode(false) }, false},
		{"documents kept", terraformOnly, docs(3), func(c *Inspector) { c.SetReleaseDocumentsAfterPayload(false) }, false},
		{"line information kept", terraformOnly, docs(3), func(c *Inspector) { c.SetReleasePostEvalData(false) }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Inspector{}
			c.SetReleaseDocumentsAfterPayload(true)
			c.SetReleasePostEvalData(true)
			c.SetCompactFindingsAtDecode(true)
			tt.set(c)
			got, ok := c.batchLargeTerraform(tt.queries, tt.payloads)
			require.Equal(t, tt.want, ok)
			if ok {
				require.Len(t, got, 3)
			}
		})
	}
}
