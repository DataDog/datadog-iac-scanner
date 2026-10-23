/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"slices"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// findingInterner shares, between the findings of one scan, the parts that
// are equal for many of them. The instances of a module block are findings on
// the same lines of the same file, so their source, surrounding lines and
// attribution are the same for every instance and every rule flagging it.
// What it returns is shared, and must only be read.
type findingInterner struct {
	mu           sync.Mutex
	strings      map[string]string
	lines        map[linesKey]*[]model.CodeLine
	attributions map[attributionKey]*model.ModuleAttribution
}

type linesKey struct {
	file string
	line int
}

// attributionKey holds everything moduleAttributionForResource reads of a
// finding besides the attribution it narrows.
type attributionKey struct {
	attribution   *model.ModuleAttribution
	line          int
	vulnerability model.ResourceLocation
	remediation   model.ResourceLocation
}

func newFindingInterner() *findingInterner {
	return &findingInterner{
		strings:      make(map[string]string),
		lines:        make(map[linesKey]*[]model.CodeLine),
		attributions: make(map[attributionKey]*model.ModuleAttribution),
	}
}

// string returns s, or an equal string seen before.
func (in *findingInterner) string(s string) string {
	if in == nil || s == "" {
		return s
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if shared, ok := in.strings[s]; ok {
		return shared
	}
	in.strings[s] = s
	return s
}

// codeLines returns lines, or equal lines seen before at the same line of the
// same file.
func (in *findingInterner) codeLines(file string, line int, lines *[]model.CodeLine) *[]model.CodeLine {
	if in == nil || lines == nil {
		return lines
	}
	key := linesKey{file: file, line: line}
	in.mu.Lock()
	defer in.mu.Unlock()
	if shared, ok := in.lines[key]; ok && slices.Equal(*shared, *lines) {
		return shared
	}
	in.lines[key] = lines
	return lines
}

// attribution returns moduleAttributionForResource(attrs, v), built once for
// the findings reading the same of it.
func (in *findingInterner) attribution(
	attrs map[string]*model.ModuleAttribution, v *model.Vulnerability,
) *model.ModuleAttribution {
	base, ok := resourceAttribution(attrs, v)
	if in == nil || !ok {
		return moduleAttributionForResource(attrs, v)
	}
	key := attributionKey{
		attribution: base, line: v.Line,
		vulnerability: v.VulnerabilityLocation, remediation: v.RemediationLocation,
	}
	in.mu.Lock()
	shared, ok := in.attributions[key]
	in.mu.Unlock()
	if ok {
		return shared
	}
	attr := moduleAttributionForResource(attrs, v)
	in.mu.Lock()
	in.attributions[key] = attr
	in.mu.Unlock()
	return attr
}
