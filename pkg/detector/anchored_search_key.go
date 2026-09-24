/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com/)  Copyright 2024 Datadog, Inc.
 */

package detector

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// Anchored search keys
//
// Some platforms (notably Ansible) emit search keys whose root segment is a
// value anchor selecting an array element, followed by a bare {{variant}}
// segment naming a key inside that element:
//
//	name={{task-name}}.{{community.aws.ecs_ecr}}.policy.Statement[0].Principal
//
// The text matcher cannot advance through bracket indices ("Statement[0]"),
// and the generic structural lookup in handleArrayIndex drops the anchor
// value, so such keys used to resolve no further than the text of the last
// plain segment before the bracket. resolveAnchoredPath resolves them
// structurally instead: the root anchor selects the element (the task) inside
// any array of the line-info document, the variant segment is validated as a
// key of that element, and the remaining segments (bracket groups expanded,
// numerics preserved) walk the element's keys. The resulting component path is
// resolved with GetLineBySearchLine against the _dd_lines markers.
//
// Only "deep" keys — whose trailing path contains a bracket index or numeric
// segment — take this path, so shallow anchored keys (e.g. ending at
// ".policy") keep the existing text-matching behavior unchanged.

// detectAnchoredLine resolves an anchored, deep search key against the file's
// line-info document. It returns nil when the key is not an anchored deep key
// or when resolution fails, so the caller falls back to the text matcher.
func detectAnchoredLine(searchKey string, file *model.FileMetadata, resolvedFile string,
	outputLines int, lines []string) *model.VulnerabilityLines {
	if file.LineInfoDocument == nil {
		return nil
	}
	splitSanitized, extractedString := splitSearchKeySegments(searchKey)
	comps, ok := resolveAnchoredPath(splitSanitized, extractedString, file.LineInfoDocument)
	if !ok {
		return nil
	}
	lineNr := GetLineBySearchLine(comps, file)
	if lineNr <= 0 || lineNr > len(lines) {
		return nil
	}
	return &model.VulnerabilityLines{
		Line:         lineNr,
		VulnLines:    GetAdjacentVulnLines(lineNr-1, outputLines, lines),
		ResolvedFile: resolvedFile,
		VulnerablilityLocation: model.ResourceLocation{
			Start: model.ResourceLine{Line: lineNr},
			End:   model.ResourceLine{Line: lineNr},
		},
	}
}

// splitSearchKeySegments extracts the {{...}} groups of a search key and splits
// the key on dots, with each group replaced by its {{index}} placeholder and
// $ref segments re-joined. This is the same normalization DetectLine applies
// before text matching, factored out so structural resolvers share it.
func splitSearchKeySegments(searchKey string) (split []string, extracted [][]string) {
	extracted = GetBracketValues(searchKey, nil, "")
	sanitized := searchKey
	for idx, str := range extracted {
		sanitized = strings.ReplaceAll(sanitized, str[0], `{{`+strconv.Itoa(idx)+`}}`)
	}
	split = strings.Split(sanitized, ".")

	// Re-join $ref segments split by dot (e.g. "$ref=#/schemas/v1.0.Foo" → ["v1","0","Foo"]).
	for index, seg := range split {
		if strings.Contains(seg, "$ref") {
			split[index] = strings.Join(split[index:], ".")
			split = split[:index+1]
			break
		}
	}
	return split, extracted
}

// resolveAnchoredPath turns sanitized search-key segments into structural
// document path components when the key is a deep anchored key; see the
// package comment. Returns false for every other key shape.
func resolveAnchoredPath(segments []string, extracted [][]string, doc map[string]interface{}) ([]string, bool) {
	if len(segments) < 2 || len(extracted) < 2 {
		return nil, false
	}
	root := segments[0]
	eq := strings.Index(root, "=")
	if eq < 0 || !strings.Contains(root, "{{") {
		return nil, false
	}
	anchorKey := root[:eq]
	anchorValue := resolvePlaceholders(root[eq+1:], extracted)
	if anchorKey == "" || anchorValue == "" {
		return nil, false
	}

	rest := segments[1:]
	variant := ""
	if strings.Contains(rest[0], "{{") && !strings.Contains(rest[0], "=") {
		variant = resolvePlaceholders(rest[0], extracted)
		if variant == "" {
			return nil, false
		}
		rest = rest[1:]
	}
	if len(rest) == 0 {
		// Shallow anchored key: keep the text-matching behavior.
		return nil, false
	}

	expanded := make([]string, 0, len(rest))
	deep := false
	for _, seg := range rest {
		seg = resolvePlaceholders(seg, extracted)
		parts := expandBracketSegment(seg)
		for _, p := range parts {
			if _, err := strconv.Atoi(p); err == nil {
				deep = true
			}
		}
		expanded = append(expanded, parts...)
	}
	if !deep {
		// No array index to walk: the text matcher handles plain key paths.
		return nil, false
	}

	elemPath, ok := findAnchoredElement(doc, anchorKey, anchorValue, variant)
	if !ok {
		return nil, false
	}
	comps := elemPath
	if variant != "" {
		comps = append(comps, variant)
	}
	return append(comps, expanded...), true
}

// resolvePlaceholders substitutes every {{index}} placeholder in seg with the
// inner value of the corresponding extracted group.
func resolvePlaceholders(seg string, extracted [][]string) string {
	for i, ext := range extracted {
		seg = strings.ReplaceAll(seg, `{{`+strconv.Itoa(i)+`}}`, ext[1])
	}
	return seg
}

// expandBracketSegment expands the bracket groups of one path segment the way
// expandSearchKeyPath does for whole keys: "Statement[0]" → ["Statement","0"].
func expandBracketSegment(seg string) []string {
	var out []string
	for seg != "" {
		open := strings.Index(seg, "[")
		if open < 0 {
			out = append(out, seg)
			break
		}
		if head := seg[:open]; head != "" {
			out = append(out, head)
		}
		closeIdx := findMatchingBracket(seg, open)
		if closeIdx < 0 {
			break
		}
		inner := seg[open+1 : closeIdx]
		inner = strings.TrimPrefix(inner, "{{")
		inner = strings.TrimSuffix(inner, "}}")
		if inner != "" {
			out = append(out, inner)
		}
		seg = seg[closeIdx+1:]
	}
	return out
}

// findAnchoredElement locates the array element whose anchorKey holds
// anchorValue (and, when variant is set, that also has a variant key), and
// returns the path components addressing it: the containing arrays walked by
// key and index (e.g. ["playbooks","0"]). Arrays are searched in document
// order; nested arrays inside non-matching elements are searched too, so
// tasks grouped under block/rescue/always keys are found as well.
func findAnchoredElement(node interface{}, anchorKey, anchorValue, variant string) ([]string, bool) {
	keys, ok := mapKeys(node)
	if !ok {
		return nil, false
	}
	for _, k := range keys {
		if skipMarkerKey(k) {
			continue
		}
		child, _ := childAt(node, k)
		switch v := child.(type) {
		case []interface{}:
			for i, e := range v {
				if anchorElementMatches(e, anchorKey, anchorValue, variant) {
					return []string{k, strconv.Itoa(i)}, true
				}
			}
			for i, e := range v {
				if p, ok := findAnchoredElement(e, anchorKey, anchorValue, variant); ok {
					return append([]string{k, strconv.Itoa(i)}, p...), true
				}
			}
		default:
			if p, ok := findAnchoredElement(child, anchorKey, anchorValue, variant); ok {
				return append([]string{k}, p...), true
			}
		}
	}
	return nil, false
}

// anchorElementMatches reports whether an array element is the one selected
// by the search key's value anchors.
func anchorElementMatches(elem interface{}, anchorKey, anchorValue, variant string) bool {
	value, ok := childAt(elem, anchorKey)
	if !ok || fmt.Sprint(value) != anchorValue {
		return false
	}
	if variant == "" {
		return true
	}
	_, ok = childAt(elem, variant)
	return ok
}

// mapKeys returns the sorted keys of a map-shaped node, so array iteration
// order is deterministic. Returns false for every other shape.
func mapKeys(node interface{}) ([]string, bool) {
	switch t := node.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return keys, true
	case model.Document:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return keys, true
	}
	return nil, false
}

// skipMarkerKey hides the line-info bookkeeping keys from the anchor search.
func skipMarkerKey(k string) bool {
	return k == "_dd_lines" || k == "_path" || k == "id" || strings.HasPrefix(k, "_dd_")
}
