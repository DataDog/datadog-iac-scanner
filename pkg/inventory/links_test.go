/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLinkKeyedEntriesBySearchKey(t *testing.T) {
	entry := func(file, path, prefix, document string, start, end int) *Resource {
		return &Resource{ResourcePath: path, Platform: "keyed", ResourceType: "entry", ResourceName: path,
			File: file, LineStart: start, LineEnd: end, Completeness: CompletenessComplete,
			DocumentID: document, searchKeyPrefix: prefix}
	}
	c := NewCollector(t.TempDir())
	c.AddResource(entry("stack.yaml", "Bucket", "Resources.Bucket", "stack", 3, 5))
	c.AddResource(entry("stack.yaml", "Queue", "Resources.Queue", "stack", 6, 8))
	c.AddResource(entry("compose.yaml", "services.web", "services.web", "compose", 2, 4))
	c.AddResource(entry("compose.yaml", "services.web.api", "services.{{web.api}}", "compose", 5, 7))
	c.AddResource(entry("single.yaml", "Topic", "Resources.Topic", "single", 4, 6))
	for _, f := range []Finding{
		// The search key wins over a line inside another entry.
		{Fingerprint: "queue-by-key", DocumentID: "stack", SearchKey: "Resources.Queue.Properties", Line: 4},
		{Fingerprint: "queue-whole-key", DocumentID: "stack", SearchKey: "Resources.Queue", Line: 1},
		// A key that names no entry falls back to the lines.
		{Fingerprint: "parameter-in-queue", DocumentID: "stack", SearchKey: "Parameters.Env.Default", Line: 7},
		{Fingerprint: "parameter-outside", DocumentID: "stack", SearchKey: "Parameters.Env.Default", Line: 1},
		// Whole segments only: services.web does not start services.{{web.api}}.
		{Fingerprint: "api", DocumentID: "compose", SearchKey: "services.{{web.api}}.ports", Line: 3},
		{Fingerprint: "web", DocumentID: "compose", SearchKey: "services.web.image", Line: 6},
		// One entry: still its key or its lines, not the whole document.
		{Fingerprint: "topic", DocumentID: "single", SearchKey: "Resources.Topic.Properties", Line: 1},
		{Fingerprint: "single-parameter", DocumentID: "single", SearchKey: "Parameters.Name.Default", Line: 1},
	} {
		c.AddFinding(&f)
	}

	inv := c.Build(testMetadata())

	require.Equal(t, []FindingLink{
		{FindingFingerprint: "api", ResourceRef: "compose.yaml|services.web.api"},
		{FindingFingerprint: "parameter-in-queue", ResourceRef: "stack.yaml|Queue"},
		{FindingFingerprint: "queue-by-key", ResourceRef: "stack.yaml|Queue"},
		{FindingFingerprint: "queue-whole-key", ResourceRef: "stack.yaml|Queue"},
		{FindingFingerprint: "topic", ResourceRef: "single.yaml|Topic"},
		{FindingFingerprint: "web", ResourceRef: "compose.yaml|services.web"},
	}, inv.FindingLinks)
	require.Equal(t, 2, inv.Stats.FindingsUnlinked, "a parameter outside every entry belongs to none")
}

func TestLinkListItemsByTheirLines(t *testing.T) {
	c := NewCollector(t.TempDir())
	for _, item := range []struct {
		path       string
		start, end int
	}{{"v1/ConfigMap//settings", 4, 9}, {"v1/Service/shop/api", 10, 14}} {
		c.AddResource(&Resource{ResourcePath: item.path, Platform: PlatformKubernetes, ResourceType: "kind",
			ResourceName: "name", File: "k8s/list.yaml", LineStart: item.start, LineEnd: item.end,
			Completeness: CompletenessComplete, DocumentID: "list"})
	}
	c.AddFinding(&Finding{Fingerprint: "on-api", DocumentID: "list", Line: 12})
	c.AddFinding(&Finding{Fingerprint: "on-list", DocumentID: "list", Line: 2})

	inv := c.Build(testMetadata())

	require.Equal(t, []FindingLink{{FindingFingerprint: "on-api", ResourceRef: "k8s/list.yaml|v1/Service/shop/api"}}, inv.FindingLinks)
	require.Equal(t, 1, inv.Stats.FindingsUnlinked, "the list itself is no resource")
}

func TestLinkRenderedListItemsByTheirKey(t *testing.T) {
	c := NewCollector(t.TempDir())
	// The objects of a list rendered from a Helm template share its line.
	for i, path := range []string{"v1/ConfigMap//settings", "v1/Service//api"} {
		c.AddResource(&Resource{ResourcePath: path, Platform: PlatformKubernetes, ResourceType: "kind",
			ResourceName: "name", File: "chart/templates/list.yaml", LineStart: 3, Completeness: CompletenessComplete,
			DocumentID: "list", searchKeyPrefix: "items." + strconv.Itoa(i), sharedLines: true})
	}
	c.AddFinding(&Finding{Fingerprint: "on-api", DocumentID: "list", SearchKey: "items.1.spec.ports", Line: 3})
	c.AddFinding(&Finding{Fingerprint: "on-settings", DocumentID: "list", SearchKey: "items[0].data.a", Line: 3})
	// At the template's line, but naming no object: the first one is not it.
	c.AddFinding(&Finding{Fingerprint: "on-list", DocumentID: "list", SearchKey: "kind", Line: 3})

	inv := c.Build(testMetadata())

	require.Equal(t, []FindingLink{
		{FindingFingerprint: "on-api", ResourceRef: "chart/templates/list.yaml|v1/Service//api"},
		{FindingFingerprint: "on-settings", ResourceRef: "chart/templates/list.yaml|v1/ConfigMap//settings"},
	}, inv.FindingLinks)
	require.Equal(t, 1, inv.Stats.FindingsUnlinked)
}

func TestSearchKeyBlock(t *testing.T) {
	for key, want := range map[string]string{
		"aws_s3_bucket[logs].acl":                                      "aws_s3_bucket.logs",
		"aws_s3_bucket[{{logs}}]":                                      "aws_s3_bucket.logs",
		"resource.aws_cloudfront_distribution[cdn].viewer_certificate": "aws_cloudfront_distribution.cdn",
		"data.aws_iam_policy_document[read].statement":                 "data.aws_iam_policy_document.read",
		"module[network].source":                                       "",
		"variable[env]":                                                "variable.env",
		"aws_s3_bucket":                                                "",
		"%s[%s]":                                                       "",
		"name={{Run}}.shell":                                           "",
	} {
		require.Equal(t, want, searchKeyBlock(key), key)
	}
	for key, want := range map[string]bool{
		"variable[env]":           true,
		"output[url].value":       true,
		"locals.region":           true,
		"module[network].source":  true,
		"provider[aws].region":    true,
		"terraform.required":      true,
		"aws_s3_bucket[logs].acl": false,
		"data.aws_ami[web]":       false,
		"resource.aws_vpc[main]":  false,
	} {
		require.Equal(t, want, namesNonResourceBlock(key), key)
	}
}

func TestLinkEveryPlaceOfAFinding(t *testing.T) {
	c := NewCollector(t.TempDir())
	c.AddResource(&Resource{ResourcePath: "Logs", Platform: "keyed", ResourceType: "AWS::S3::Bucket", ResourceName: "shared",
		File: "stack.yaml", LineStart: 2, LineEnd: 5, Completeness: CompletenessComplete, DocumentID: "stack", searchKeyPrefix: "Resources.Logs"})
	c.AddResource(&Resource{ResourcePath: "Backup", Platform: "keyed", ResourceType: "AWS::S3::Bucket", ResourceName: "shared",
		File: "stack.yaml", LineStart: 6, LineEnd: 9, Completeness: CompletenessComplete, DocumentID: "stack", searchKeyPrefix: "Resources.Backup"})
	// One finding the scan kept for two buckets, and one whose places are on
	// no resource.
	c.AddFinding(&Finding{Fingerprint: "shared", DocumentID: "stack", SearchKey: "Resources.Logs.Properties", Line: 4})
	c.AddFinding(&Finding{Fingerprint: "shared", DocumentID: "stack", SearchKey: "Resources.Backup.Properties", Line: 8})
	c.AddFinding(&Finding{Fingerprint: "parameters", DocumentID: "stack", SearchKey: "Parameters.A", Line: 20})
	c.AddFinding(&Finding{Fingerprint: "parameters", DocumentID: "stack", SearchKey: "Parameters.B", Line: 21})

	inv := c.Build(testMetadata())

	require.Equal(t, []FindingLink{
		{FindingFingerprint: "shared", ResourceRef: "stack.yaml|Backup"},
		{FindingFingerprint: "shared", ResourceRef: "stack.yaml|Logs"},
	}, inv.FindingLinks)
	require.Equal(t, 1, inv.Stats.FindingsUnlinked, "a finding is unlinked once, when none of its places is on a resource")
}
