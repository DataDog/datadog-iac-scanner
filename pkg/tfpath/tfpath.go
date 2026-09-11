/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package tfpath holds path predicates for Terraform/OpenTofu config files.
package tfpath

import (
	"path/filepath"
	"strings"
)

const (
	ExtTF       = ".tf"
	ExtTofu     = ".tofu"
	ExtTFJSON   = ".tf.json"
	ExtTofuJSON = ".tofu.json"
	ExtTFVars   = ".tfvars"
)

// Extension returns the Terraform/OpenTofu config suffix, including compound
// JSON suffixes that filepath.Ext would truncate to ".json".
func Extension(path string) string {
	switch {
	case hasExtSuffix(path, ExtTofuJSON):
		return ExtTofuJSON
	case hasExtSuffix(path, ExtTFJSON):
		return ExtTFJSON
	default:
		return filepath.Ext(path)
	}
}

// IsJSONConfig reports whether path uses Terraform/OpenTofu JSON configuration syntax.
func IsJSONConfig(path string) bool {
	return hasExtSuffix(path, ExtTofuJSON) || hasExtSuffix(path, ExtTFJSON)
}

func hasExtSuffix(path, ext string) bool {
	return len(path) >= len(ext) && strings.EqualFold(path[len(path)-len(ext):], ext)
}

// IsHCLConfig reports whether path is a native Terraform/OpenTofu HCL configuration file.
func IsHCLConfig(path string) bool {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ExtTFVars) {
		return false
	}
	return strings.HasSuffix(lower, ExtTF) || strings.HasSuffix(lower, ExtTofu)
}

// IsConfig reports whether path may declare Terraform/OpenTofu modules.
func IsConfig(path string) bool {
	return IsHCLConfig(path) || IsJSONConfig(path)
}

// Matching keeps paths that satisfy pred. It does not apply OpenTofu precedence.
func Matching(paths []string, pred func(string) bool) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if pred(p) {
			out = append(out, p)
		}
	}
	return out
}

// Select is Matching then FilterShadowed. Use it when merging a directory into
// one module, not when deciding which files enter inventory.
func Select(paths []string, pred func(string) bool) []string {
	return FilterShadowed(Matching(paths, pred))
}

// SelectWithTofuPrecedence applies OpenTofu precedence only when preferTofu
// accepts the .tofu path. If a twin exists and preferTofu rejects it, the .tf
// path is kept instead.
func SelectWithTofuPrecedence(paths []string, pred, preferTofu func(string) bool) []string {
	kept, _ := PartitionWithTofuPrecedence(Matching(paths, pred), func(p string) string { return p }, preferTofu)
	return kept
}

// SelectKeeping is Select, except keep stays in the result when it matched pred.
// If keep is a .tf twin of a selected .tofu file, that .tofu twin is dropped so a
// scanned Terraform file is not evaluated with its OpenTofu replacement.
func SelectKeeping(paths []string, pred func(string) bool, keep string) []string {
	return SelectKeepingWithTofuPrecedence(paths, pred, keep, nil)
}

// SelectKeepingWithTofuPrecedence is SelectWithTofuPrecedence, except keep
// stays in the result and its twin is dropped.
func SelectKeepingWithTofuPrecedence(
	paths []string, pred func(string) bool, keep string, preferTofu func(string) bool,
) []string {
	matched := Matching(paths, pred)
	selected, _ := PartitionWithTofuPrecedence(matched, func(p string) string { return p }, preferTofu)
	if keep == "" {
		return selected
	}
	var keepPath string
	for _, p := range matched {
		if configPathEqual(p, keep) {
			keepPath = p
			break
		}
	}
	if keepPath == "" {
		return selected
	}
	for _, p := range selected {
		if configPathEqual(p, keepPath) {
			return selected
		}
	}
	keepKey, ok := configKey(keepPath)
	out := make([]string, 0, len(selected)+1)
	for _, p := range selected {
		if ok {
			if key, isConfig := configKey(p); isConfig && key == keepKey {
				continue
			}
		}
		out = append(out, p)
	}
	return append(out, keepPath)
}

// AllowSet indexes inventory paths for merge filtering.
func AllowSet(paths []string) map[string]struct{} {
	if len(paths) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(paths)*2)
	for _, path := range paths {
		out[filepath.ToSlash(path)] = struct{}{}
		out[filepath.ToSlash(filepath.Clean(path))] = struct{}{}
	}
	return out
}

func configPathEqual(a, b string) bool {
	ad, ab := splitDirBase(a)
	bd, bb := splitDirBase(b)
	return ad == bd && ab == bb
}

// ShadowedByTofu reports paths OpenTofu ignores: foo.tf next to foo.tofu,
// foo.tf.json next to foo.tofu.json. Returns nil when nothing is shadowed.
func ShadowedByTofu(paths []string) map[string]struct{} {
	var tofuKeys map[string]struct{}
	for _, p := range paths {
		if key, ok := shadowKey(p, ExtTofuJSON, ExtTofu); ok {
			if tofuKeys == nil {
				tofuKeys = make(map[string]struct{})
			}
			tofuKeys[key] = struct{}{}
		}
	}
	if tofuKeys == nil {
		return nil
	}
	var shadowed map[string]struct{}
	for _, p := range paths {
		key, ok := shadowKey(p, ExtTFJSON, ExtTF)
		if !ok {
			continue
		}
		if _, hit := tofuKeys[key]; !hit {
			continue
		}
		if shadowed == nil {
			shadowed = make(map[string]struct{})
		}
		shadowed[p] = struct{}{}
	}
	return shadowed
}

// FilterShadowed drops paths ShadowedByTofu reports. The input is returned
// unchanged when nothing is shadowed.
func FilterShadowed(paths []string) []string {
	kept, _ := Partition(paths, func(p string) string { return p })
	return kept
}

// Partition splits items into those OpenTofu would load and those it ignores.
// shadowed is nil when nothing is dropped; kept is the input slice in that case.
func Partition[T any](items []T, path func(T) string) (kept, shadowed []T) {
	return PartitionWithTofuPrecedence(items, path, nil)
}

// PartitionWithTofuPrecedence splits twin configs according to preferTofu.
// A nil callback gives every .tofu path precedence.
func PartitionWithTofuPrecedence[T any](
	items []T, path func(T) string, preferTofu func(string) bool,
) (kept, shadowed []T) {
	if len(items) == 0 {
		return items, nil
	}
	tfKeys := make(map[string]struct{})
	preferredTofuKeys := make(map[string]struct{})
	for i := range items {
		p := path(items[i])
		if key, ok := shadowKey(p, ExtTFJSON, ExtTF); ok {
			tfKeys[key] = struct{}{}
		}
		if key, ok := shadowKey(p, ExtTofuJSON, ExtTofu); ok &&
			(preferTofu == nil || preferTofu(p)) {
			preferredTofuKeys[key] = struct{}{}
		}
	}
	kept = make([]T, 0, len(items))
	for i := range items {
		p := path(items[i])
		drop := false
		if key, ok := shadowKey(p, ExtTFJSON, ExtTF); ok {
			_, drop = preferredTofuKeys[key]
		} else if key, ok := shadowKey(p, ExtTofuJSON, ExtTofu); ok {
			_, hasTwin := tfKeys[key]
			_, preferred := preferredTofuKeys[key]
			drop = hasTwin && !preferred
		}
		if drop {
			shadowed = append(shadowed, items[i])
			continue
		}
		kept = append(kept, items[i])
	}
	if len(shadowed) == 0 {
		return items, nil
	}
	return kept, shadowed
}

func shadowKey(path, jsonExt, hclExt string) (string, bool) {
	dir, base := splitDirBase(path)
	lowerBase := strings.ToLower(base)
	if strings.HasSuffix(lowerBase, jsonExt) {
		return dir + base[:len(base)-len(jsonExt)] + "\x00json", true
	}
	if strings.HasSuffix(lowerBase, hclExt) {
		return dir + base[:len(base)-len(hclExt)] + "\x00hcl", true
	}
	return "", false
}

func configKey(path string) (string, bool) {
	if key, ok := shadowKey(path, ExtTFJSON, ExtTF); ok {
		return key, true
	}
	return shadowKey(path, ExtTofuJSON, ExtTofu)
}

func splitDirBase(path string) (dir, base string) {
	sep := strings.LastIndexAny(path, `/\`)
	if sep < 0 {
		return "", path
	}
	return path[:sep+1], path[sep+1:]
}
