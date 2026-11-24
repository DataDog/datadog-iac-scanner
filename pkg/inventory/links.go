/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import (
	"math"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/platforms"
)

// Finding is what links a finding to the rows it belongs to.
type Finding struct {
	// Fingerprint is the finding's DATADOG_FINGERPRINT.
	Fingerprint string
	// DocumentID is the document the finding was raised on.
	DocumentID string
	// File is the path of that document's file, and Line the finding's line.
	File string
	Line int
	// SearchKey is the finding's search key, which names the entry of a keyed
	// collection the finding is on.
	SearchKey string
	// BlockStart is the first line of the Terraform block the finding is on,
	// and ModuleCallChain the module calls that block was reached through.
	BlockStart      int
	ModuleCallChain string
	// Block names the affected Terraform declaration when its location is
	// separate from the finding's source.
	Block string
}

// AddFinding records a finding to link to the rows when the inventory is built.
func (c *Collector) AddFinding(f *Finding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.built != nil {
		return
	}
	c.findings = append(c.findings, *f)
}

type terraformScope struct{ file, chain string }

// terraformStart is where Terraform rows start in a scope.
type terraformStart struct {
	terraformScope
	line int
}

// linkFindings links each recorded finding to its rows, which must be
// finished, and counts those that belong to none.
//
//   - A finding on a document that is one resource, a Kubernetes object or a
//     Dockerfile, belongs to its row.
//   - A finding on an entry of a keyed collection (CloudFormation Resources,
//     Compose services) belongs to the entry its search key names, else to
//     the narrowest row whose lines hold the finding. So does a finding on
//     any other row, such as an Ansible task, however many rows its document
//     holds: a play-level finding belongs to no task.
//   - Rows that share a reference but for its suffix, such as two documents
//     of a file with the same name, are told apart by their document or key
//     like any other. A finding the scan raised on several of them and kept
//     once carries every place it was raised (Finding per place), so each
//     links its own row, whichever the scan kept.
//   - A Terraform finding belongs to every instance of its block, reached
//     through the same module calls: the instances of a count or for_each
//     block share their findings. Its block is the one starting where the
//     finding's block does; when several start there, as in compact JSON
//     configuration, the one its search key names (aws_s3_bucket[logs]).
func (c *Collector) linkFindings(rows []Resource) (links []FindingLink, unlinked int) {
	byDocument := make(map[string][]int)
	byScope := make(map[terraformScope][]int)
	byStart := make(map[terraformStart][]int)
	for i := range rows {
		r := &rows[i]
		if r.DocumentID != "" {
			byDocument[r.DocumentID] = append(byDocument[r.DocumentID], i)
		}
		if r.Platform == platforms.Terraform {
			key := terraformScope{r.File, r.ModuleCallChain}
			byScope[key] = append(byScope[key], i)
			start := terraformStart{key, r.LineStart}
			byStart[start] = append(byStart[start], i)
		}
	}
	// A finding can be recorded at several places, the duplicates the scan
	// dropped for it: it is unlinked only when none of them belongs to a row.
	linked := make(map[string]bool, len(c.findings))
	for i := range c.findings {
		f := &c.findings[i]
		if _, seen := linked[f.Fingerprint]; !seen {
			linked[f.Fingerprint] = false
		}
		matched := matchDocument(rows, byDocument[f.DocumentID], f)
		if len(matched) == 0 && f.File != "" {
			scope := terraformScope{c.resourcePath(f.File), f.ModuleCallChain}
			matched = matchTerraform(rows, byScope[scope], byStart[terraformStart{scope, f.BlockStart}], f)
		}
		for _, j := range matched {
			links = append(links, FindingLink{FindingFingerprint: f.Fingerprint, ResourceRef: rows[j].ResourceRef})
		}
		if len(matched) > 0 {
			linked[f.Fingerprint] = true
		}
	}
	for _, ok := range linked {
		if !ok {
			unlinked++
		}
	}
	return links, unlinked
}

func matchDocument(rows []Resource, candidates []int, f *Finding) []int {
	if len(candidates) == 1 && rows[candidates[0]].ownsDocument {
		return candidates
	}
	if j, ok := namedBySearchKey(rows, candidates, f.SearchKey); ok {
		return []int{j}
	}
	// Rows whose lines are not their own take a finding by its key only.
	own := make([]int, 0, len(candidates))
	for _, j := range candidates {
		if !rows[j].sharedLines {
			own = append(own, j)
		}
	}
	if j, ok := narrowestHolding(rows, own, f.Line); ok {
		return []int{j}
	}
	return nil
}

// namedBySearchKey returns the candidate entry of a keyed collection, or
// object of a list, that the search key starts with, whole segments only. A
// list index is read as written either way: items.0 or items[0].
func namedBySearchKey(rows []Resource, candidates []int, searchKey string) (int, bool) {
	if strings.Contains(searchKey, "items[") {
		parts := strings.Split(searchKey, ".")
		for i, part := range parts {
			if rest, ok := strings.CutPrefix(part, "items["); ok {
				if index, after, found := strings.Cut(rest, "]"); found {
					parts[i] = "items." + index + after
				}
			}
		}
		searchKey = strings.Join(parts, ".")
	}
	for _, j := range candidates {
		prefix := rows[j].searchKeyPrefix
		if prefix != "" && (searchKey == prefix || strings.HasPrefix(searchKey, prefix+".")) {
			return j, true
		}
	}
	return -1, false
}

// matchTerraform returns the instances of a Terraform finding's block among
// the rows of its scope, given those that start where its block does.
func matchTerraform(rows []Resource, candidates, atStart []int, f *Finding) []int {
	// A finding on a variable, an output or another block that is not a
	// resource belongs to no row, whatever shares its line.
	if namesNonResourceBlock(f.SearchKey) {
		return nil
	}
	if f.Block != "" {
		// The declaration is known even when the inventory has no row for
		// it. The source line can belong to another file.
		return ofBlock(rows, atStart, f.Block)
	}
	block := searchKeyBlock(f.SearchKey)
	if f.BlockStart > 0 && len(atStart) > 0 {
		if named := ofBlock(rows, atStart, block); len(named) > 0 {
			return named
		}
		return atStart
	}
	// Without a block start, the block whose lines hold the finding, with
	// every instance of it.
	if named := ofBlock(rows, candidates, block); len(named) > 0 {
		if _, ok := narrowestHolding(rows, named, f.Line); ok {
			return named
		}
	}
	j, ok := narrowestHolding(rows, candidates, f.Line)
	if !ok {
		return nil
	}
	var matched []int
	for _, k := range candidates {
		if rows[k].LineStart == rows[j].LineStart && rows[k].Block == rows[j].Block {
			matched = append(matched, k)
		}
	}
	return matched
}

// ofBlock returns the rows that are instances of block, none for "".
func ofBlock(rows []Resource, candidates []int, block string) []int {
	if block == "" {
		return nil
	}
	var named []int
	for _, j := range candidates {
		if rows[j].Block == block {
			named = append(named, j)
		}
	}
	return named
}

// nonResourceBlocks are the top-level Terraform blocks that hold no resource.
var nonResourceBlocks = map[string]bool{
	"variable": true, "output": true, "locals": true, "module": true, "provider": true,
	"terraform": true, "moved": true, "import": true, "removed": true, "check": true,
}

// namesNonResourceBlock reports a Terraform search key that starts with a
// block holding no resource, such as variable[env] or output.url.
func namesNonResourceBlock(searchKey string) bool {
	head := searchKey
	if i := strings.IndexAny(head, "[."); i >= 0 {
		head = head[:i]
	}
	return nonResourceBlocks[head]
}

// searchKeyBlock returns the block a Terraform search key starts with, as
// rows name it: aws_s3_bucket.logs for aws_s3_bucket[logs] or
// resource.aws_s3_bucket[{{logs}}], data.aws_ami.web for data.aws_ami[web].
// It returns "" for a key that names no resource or data block.
func searchKeyBlock(searchKey string) string {
	key := strings.TrimPrefix(searchKey, "resource.")
	kind := ""
	if rest, ok := strings.CutPrefix(key, "data."); ok {
		kind, key = "data.", rest
	}
	open := strings.IndexByte(key, '[')
	end := strings.IndexByte(key, ']')
	if open <= 0 || end < open {
		return ""
	}
	typ := key[:open]
	if typ == "module" || strings.IndexFunc(typ, func(r rune) bool {
		return r != '_' && r != '-' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9')
	}) >= 0 {
		return ""
	}
	name := strings.TrimSuffix(strings.TrimPrefix(key[open+1:end], "{{"), "}}")
	if name == "" {
		return ""
	}
	return kind + typ + "." + name
}

// narrowestHolding returns the candidate row with the fewest lines that holds
// line.
func narrowestHolding(rows []Resource, candidates []int, line int) (int, bool) {
	best, width := -1, math.MaxInt
	for _, j := range candidates {
		r := &rows[j]
		start, end := r.LineStart, max(r.LineEnd, r.LineStart)
		if r.linkFallbackLine != 0 {
			start, end = r.linkFallbackLine, r.linkFallbackLine
		}
		if line < start || line > end {
			continue
		}
		w := end - start
		if w < width || (w == width && preferCollectionEntry(r, &rows[best])) {
			best, width = j, w
		}
	}
	return best, best >= 0
}

// A generated row sorts by its loop's span in the report. For a tie on the
// collection line, keep the order by logical ID used before it moved.
func preferCollectionEntry(row, best *Resource) bool {
	return (row.linkFallbackLine != 0 || best.linkFallbackLine != 0) && row.ResourcePath < best.ResourcePath
}
