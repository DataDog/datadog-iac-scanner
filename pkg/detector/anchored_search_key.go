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

// Anchored search keys (notably Ansible) start with a value anchor selecting
// an array element, optionally followed by a bare {{variant}} segment naming a
// key inside that element:
//
//	name={{task}}.{{community.aws.ecs_ecr}}.policy.Statement[0].Principal
//
// The text matcher cannot advance through bracket indices, so deep anchored
// keys are resolved structurally here; shallow ones keep text matching.

// detectAnchoredLine resolves a deep anchored search key against the file's
// line-info document. Returns nil when the key is not anchored or resolution
// fails, so the caller falls back to the text matcher.
func detectAnchoredLine(searchKey string, file *model.FileMetadata, resolvedFile string,
	outputLines int, lines []string) *model.VulnerabilityLines {
	if file.LineInfoDocument == nil {
		return nil
	}
	segments, extracted := splitSearchKeySegments(searchKey)
	comps, ok := resolveAnchoredPath(segments, extracted, file.LineInfoDocument)
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
// the key on dots, each group replaced by its {{index}} placeholder. The
// split is bracket-aware, so dots inside groups like labels["foo.bar"] are
// preserved (mirroring expandSearchKeyPath).
func splitSearchKeySegments(searchKey string) (split []string, extracted [][]string) {
	extracted = GetBracketValues(searchKey, nil, "")
	sanitized := searchKey
	for idx, str := range extracted {
		sanitized = strings.ReplaceAll(sanitized, str[0], `{{`+strconv.Itoa(idx)+`}}`)
	}
	split = splitTopLevelDots(sanitized)

	// Re-join $ref segments split by dot (e.g. "$ref=#/schemas/v1.0.Foo").
	for index, seg := range split {
		if strings.Contains(seg, "$ref") {
			split[index] = strings.Join(split[index:], ".")
			split = split[:index+1]
			break
		}
	}
	return split, extracted
}

// anchoredKeyPrefix holds the value anchors that select the array element a
// search key points into.
type anchoredKeyPrefix struct {
	anchorKey   string
	anchorValue string
	variant     string
}

// resolveAnchoredPath turns sanitized search-key segments into structural
// document path components for a deep anchored key. Returns false for every
// other key shape.
func resolveAnchoredPath(segments []string, extracted [][]string, doc map[string]interface{}) ([]string, bool) {
	prefix, rest, ok := parseAnchoredPrefix(segments, extracted)
	if !ok || len(rest) == 0 {
		return nil, false
	}
	expanded := expandKeyPath(rest, extracted)
	if !hasNumericIndex(expanded) {
		return nil, false
	}
	elemPath, ok := findAnchoredElement(doc, prefix.anchorKey, prefix.anchorValue, prefix.variant)
	if !ok {
		return nil, false
	}
	comps := elemPath
	if prefix.variant != "" {
		comps = append(comps, prefix.variant)
	}
	return append(comps, expanded...), true
}

// parseAnchoredPrefix parses the leading "key={{value}}" anchor segment and,
// when present, the bare {{variant}} segment following it. ok is false when
// the key is not anchored in this shape.
func parseAnchoredPrefix(segments []string, extracted [][]string) (prefix anchoredKeyPrefix, rest []string, ok bool) {
	if len(segments) < 2 || len(extracted) < 1 {
		return prefix, nil, false
	}
	root := segments[0]
	eq := strings.Index(root, "=")
	if eq < 0 || !strings.Contains(root, "{{") {
		return prefix, nil, false
	}
	prefix.anchorKey = root[:eq]
	prefix.anchorValue = resolvePlaceholders(root[eq+1:], extracted)
	if prefix.anchorKey == "" || prefix.anchorValue == "" {
		return prefix, nil, false
	}
	rest = segments[1:]
	if strings.Contains(rest[0], "{{") && !strings.Contains(rest[0], "=") {
		prefix.variant = resolvePlaceholders(rest[0], extracted)
		if prefix.variant == "" {
			return prefix, nil, false
		}
		rest = rest[1:]
	}
	return prefix, rest, true
}

// resolvePlaceholders substitutes every {{index}} placeholder in seg with the
// inner value of the corresponding extracted group.
func resolvePlaceholders(seg string, extracted [][]string) string {
	for i, ext := range extracted {
		seg = strings.ReplaceAll(seg, `{{`+strconv.Itoa(i)+`}}`, ext[1])
	}
	return seg
}

// expandKeyPath resolves placeholders in and expands the bracket groups of the
// trailing path segments: "Statement[0].Principal" → ["Statement", "0", "Principal"].
func expandKeyPath(segments []string, extracted [][]string) []string {
	out := make([]string, 0, len(segments))
	for _, seg := range segments {
		out = append(out, expandBracketSegment(resolvePlaceholders(seg, extracted))...)
	}
	return out
}

// hasNumericIndex reports whether the path walks an array element, which the
// text matcher cannot do.
func hasNumericIndex(parts []string) bool {
	for _, p := range parts {
		if _, err := strconv.Atoi(p); err == nil {
			return true
		}
	}
	return false
}

// expandBracketSegment expands the bracket groups of one path segment,
// mirroring expandSearchKeyPath: "Statement[0]" → ["Statement", "0"].
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
		inner := strings.TrimSuffix(strings.TrimPrefix(seg[open+1:closeIdx], "{{"), "}}")
		inner = unquoteKey(inner)
		if inner != "" {
			out = append(out, inner)
		}
		seg = seg[closeIdx+1:]
	}
	return out
}

// findAnchoredElement locates the array element selected by the anchors and
// returns the path components addressing it (e.g. ["playbooks","0"]). Nested
// arrays are searched too, so tasks under block/rescue/always keys are found.
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

// unquoteKey strips the quotes of a quoted bracket key: labels["foo.bar"]
// addresses the map key foo.bar.
func unquoteKey(inner string) string {
	if len(inner) < 2 || inner[0] != '"' || inner[len(inner)-1] != '"' {
		return inner
	}
	if unquoted, err := strconv.Unquote(inner); err == nil {
		return unquoted
	}
	return inner[1 : len(inner)-1]
}

// anchorElementMatches reports whether an array element is the one selected by
// the search key's value anchors.
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

// mapKeys returns the sorted keys of a map-shaped node so array iteration
// order is deterministic. Returns false for every other shape.
func mapKeys(node interface{}) ([]string, bool) {
	var t map[string]interface{}
	switch typed := node.(type) {
	case map[string]interface{}:
		t = typed
	case model.Document:
		t = typed
	default:
		return nil, false
	}
	keys := make([]string, 0, len(t))
	for k := range t {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, true
}

// skipMarkerKey hides the line-info bookkeeping keys from the anchor search.
func skipMarkerKey(k string) bool {
	return k == "_dd_lines" || k == "_path" || k == "id" || strings.HasPrefix(k, "_dd_")
}
