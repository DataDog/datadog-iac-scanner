/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/platforms"
	"github.com/stretchr/testify/require"
)

func TestLinkRepeatedListObjectsByTheirKey(t *testing.T) {
	c := NewCollector(t.TempDir())
	// Add identical list objects in reverse order. The second still takes
	// the #2 reference, and the finding carries that exact occurrence.
	for _, i := range []int{1, 0} {
		o := &model.ResourceOccurrence{
			DocumentID:     "list",
			StructuralPath: model.SourcePath{{Key: "items"}, {Index: i, IsIndex: true}},
			ResourcePath:   "v1/ConfigMap//same", Platform: platforms.Kubernetes,
			ResourceType: "ConfigMap", ResourceName: "same", File: "chart/templates/list.yaml",
			Source: model.ResourceLocation{Start: model.ResourceLine{Line: 3}},
		}
		row := ProjectResource(o)
		c.AddResource(&row)
		if i == 1 {
			c.AddFinding(&Finding{Fingerprint: "on-second", Occurrences: []*model.ResourceOccurrence{o}})
		}
	}

	inv := c.Build(testMetadata())
	require.Equal(t, []FindingLink{
		{FindingFingerprint: "on-second", ResourceRef: "chart/templates/list.yaml|v1/ConfigMap//same#2"},
	}, inv.FindingLinks)
}

func TestLinkEveryOccurrenceOfAFinding(t *testing.T) {
	c := NewCollector(t.TempDir())
	logs := &model.ResourceOccurrence{ResourcePath: "Logs", File: "stack.yaml"}
	backup := &model.ResourceOccurrence{ResourcePath: "Backup", File: "stack.yaml"}
	for _, o := range []*model.ResourceOccurrence{logs, backup} {
		row := ProjectResource(o)
		c.AddResource(&row)
	}
	c.AddFinding(&Finding{Fingerprint: "shared", Occurrences: []*model.ResourceOccurrence{logs, backup}})
	c.AddFinding(&Finding{Fingerprint: "shared"})
	c.AddFinding(&Finding{Fingerprint: "parameters"})
	c.AddFinding(&Finding{Fingerprint: "parameters"})

	inv := c.Build(testMetadata())
	require.Equal(t, []FindingLink{
		{FindingFingerprint: "shared", ResourceRef: "stack.yaml|Backup"},
		{FindingFingerprint: "shared", ResourceRef: "stack.yaml|Logs"},
	}, inv.FindingLinks)
	require.Equal(t, 1, inv.Stats.FindingsUnlinked)
}
