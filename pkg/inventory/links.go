/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import "math"

// Finding is what links a finding to the rows it belongs to.
type Finding struct {
	// Fingerprint is the finding's DATADOG_FINGERPRINT.
	Fingerprint string
	// DocumentID is the document the finding was raised on.
	DocumentID string
	// File is the path of that document's file, and Line the finding's line.
	File string
	Line int
	// BlockStart is the first line of the Terraform block the finding is on,
	// and ModuleCallChain the module calls that block was reached through.
	BlockStart      int
	ModuleCallChain string
}

// AddFinding records a finding to link to the rows when the inventory is built.
func (c *Collector) AddFinding(f *Finding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.findings = append(c.findings, *f)
}

type terraformScope struct{ file, chain string }

// linkFindings links each recorded finding to its rows, which must be
// finished, and counts those that belong to none.
//
//   - A finding on a document that holds one row belongs to it; on a document
//     that holds several, to the narrowest row whose lines hold the finding.
//   - A Terraform finding belongs to every instance of its block, reached
//     through the same module calls: the instances of a count or for_each
//     block share their findings.
func (c *Collector) linkFindings(rows []Resource) (links []FindingLink, unlinked int) {
	byDocument := make(map[string][]int)
	byScope := make(map[terraformScope][]int)
	for i := range rows {
		r := &rows[i]
		if r.DocumentID != "" {
			byDocument[r.DocumentID] = append(byDocument[r.DocumentID], i)
		}
		if r.Platform == PlatformTerraform {
			key := terraformScope{r.File, r.ModuleCallChain}
			byScope[key] = append(byScope[key], i)
		}
	}
	for i := range c.findings {
		f := &c.findings[i]
		matched := matchDocument(rows, byDocument[f.DocumentID], f.Line)
		if len(matched) == 0 && f.File != "" {
			matched = matchTerraform(rows, byScope[terraformScope{c.resourcePath(f.File), f.ModuleCallChain}], f)
		}
		if len(matched) == 0 {
			unlinked++
			continue
		}
		for _, j := range matched {
			links = append(links, FindingLink{FindingFingerprint: f.Fingerprint, ResourceRef: rows[j].ResourceRef})
		}
	}
	return links, unlinked
}

func matchDocument(rows []Resource, candidates []int, line int) []int {
	if len(candidates) == 1 {
		return candidates
	}
	if j, ok := narrowestHolding(rows, candidates, line); ok {
		return []int{j}
	}
	return nil
}

func matchTerraform(rows []Resource, candidates []int, f *Finding) []int {
	var matched []int
	if f.BlockStart > 0 {
		for _, j := range candidates {
			if rows[j].LineStart == f.BlockStart {
				matched = append(matched, j)
			}
		}
	}
	if len(matched) > 0 {
		return matched
	}
	// Without a block start, the block whose lines hold the finding, with
	// every instance of it.
	j, ok := narrowestHolding(rows, candidates, f.Line)
	if !ok {
		return nil
	}
	for _, k := range candidates {
		if rows[k].LineStart == rows[j].LineStart {
			matched = append(matched, k)
		}
	}
	return matched
}

// narrowestHolding returns the candidate row with the fewest lines that holds
// line.
func narrowestHolding(rows []Resource, candidates []int, line int) (int, bool) {
	best, width := -1, math.MaxInt
	for _, j := range candidates {
		r := &rows[j]
		end := max(r.LineEnd, r.LineStart)
		if line < r.LineStart || line > end {
			continue
		}
		if w := end - r.LineStart; w < width {
			best, width = j, w
		}
	}
	return best, best >= 0
}
