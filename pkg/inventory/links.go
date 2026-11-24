/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import "github.com/DataDog/datadog-iac-scanner/pkg/model"

// Finding carries the fingerprint reported in SARIF and its affected
// declaration instances.
type Finding struct {
	Fingerprint string
	Occurrences []*model.ResourceOccurrence
}

// AddFinding records a finding for the inventory.
func (c *Collector) AddFinding(f *Finding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.built != nil {
		return
	}
	c.findings = append(c.findings, *f)
}

// linkFindings joins occurrences to their final, unique row references.
func (c *Collector) linkFindings(rows []Resource) (links []FindingLink, unlinked int) {
	refs := make(map[*model.ResourceOccurrence]string, len(rows))
	for i := range rows {
		if rows[i].occurrence != nil {
			refs[rows[i].occurrence] = rows[i].ResourceRef
			rows[i].occurrence = nil
		}
	}
	linked := make(map[string]bool, len(c.findings))
	for _, finding := range c.findings {
		found := linked[finding.Fingerprint]
		for _, occurrence := range finding.Occurrences {
			if ref, ok := refs[occurrence]; ok {
				links = append(links, FindingLink{FindingFingerprint: finding.Fingerprint, ResourceRef: ref})
				found = true
			}
		}
		linked[finding.Fingerprint] = found
	}
	for _, found := range linked {
		if !found {
			unlinked++
		}
	}
	return links, unlinked
}
