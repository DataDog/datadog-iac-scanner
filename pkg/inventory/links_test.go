/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import (
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
