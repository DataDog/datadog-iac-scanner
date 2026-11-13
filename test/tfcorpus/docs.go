/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfcorpus

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// NormalizeDocs renders the legacy documents of one scanned cell as stable
// bytes, so two engine builds compare by content. Documents are keyed by the
// cell directory and the file they were written on, relative to the cell
// root with forward slashes; the document id (a file id of the run) is
// dropped; documents written on the same file sort by their content, so per
// module instance documents compare as a set. Both engine builds that produce
// these documents use this one function, so only the documents themselves can
// differ.
func NormalizeDocs(cellRoot string, docs []map[string]any) []byte {
	keyed := map[string][]map[string]any{}
	for _, doc := range docs {
		out := map[string]any{}
		for k, v := range doc {
			if k == "id" {
				continue
			}
			out[k] = v
		}
		if file, ok := out["file"].(string); ok {
			rel, err := filepath.Rel(cellRoot, filepath.FromSlash(file))
			if err == nil {
				out["file"] = filepath.ToSlash(rel)
			}
		}
		key := ""
		if file, ok := out["file"].(string); ok {
			key = file
		}
		keyed[key] = append(keyed[key], out)
	}
	// Documents written on the same file sort by content.
	for _, list := range keyed {
		sort.Slice(list, func(i, j int) bool {
			a, _ := json.Marshal(list[i])
			b, _ := json.Marshal(list[j])
			return string(a) < string(b)
		})
	}
	keys := make([]string, 0, len(keyed))
	for k := range keyed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ordered := map[string]any{}
	for _, k := range keys {
		ordered[k] = keyed[k]
	}
	b, err := json.MarshalIndent(ordered, "", " ")
	if err != nil {
		panic(err)
	}
	return b
}

// WriteGolden writes normalized bytes to path, creating parent directories.
func WriteGolden(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, content, 0o600)
}

// CellsSample takes every nth cell, starting with the first.
func CellsSample(cells []Cell, nth int) []Cell {
	var out []Cell
	for i := 0; i < len(cells); i += nth {
		out = append(out, cells[i])
	}
	return out
}

// HasPrefixPath reports whether the JSON pointer p starts with the given
// segments.
func HasPrefixPath(p string, segments ...string) bool {
	rest := strings.TrimPrefix(p, "/")
	for _, seg := range segments {
		if !strings.HasPrefix(rest, seg) {
			return false
		}
		rest = strings.TrimPrefix(rest, seg)
		if !strings.HasPrefix(rest, "/") && rest != "" {
			return false
		}
		rest = strings.TrimPrefix(rest, "/")
	}
	return true
}
