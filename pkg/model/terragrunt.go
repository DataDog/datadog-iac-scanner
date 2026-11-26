/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

import "sort"

// LineMapping maps the virtual lines FromLine..ToLine (inclusive) of a
// translation to the item of a real file that produced them.
type LineMapping struct {
	FromLine int
	ToLine   int
	// Argument is the module argument written on these lines: "source", an
	// input name, or "" for the module block itself (its first and last line).
	Argument string
	// Real is the position in the real file. Its Filename is the absolute path
	// the file was parsed under; lines and columns are 1-based and the end is
	// exclusive, as in hcl.Range.
	Real SourceLocation
}

// LineTable maps virtual lines to real positions. Mappings are sorted by
// FromLine and do not overlap.
type LineTable []LineMapping

// Lookup returns the mapping that holds virtual line, if any.
func (t LineTable) Lookup(line int) (LineMapping, bool) {
	i := sort.Search(len(t), func(i int) bool { return t[i].ToLine >= line })
	if i < len(t) && t[i].FromLine <= line {
		return t[i], true
	}
	return LineMapping{}, false
}

// Argument returns the mapping of a module argument by name.
func (t LineTable) Argument(name string) (LineMapping, bool) {
	for _, m := range t {
		if m.Argument == name && name != "" {
			return m, true
		}
	}
	return LineMapping{}, false
}

// LookupOrAnchor returns the mapping that holds virtual line, else the anchor (the
// module block), else false.
func (t LineTable) LookupOrAnchor(line int) (LineMapping, bool) {
	if m, ok := t.Lookup(line); ok {
		return m, true
	}
	return t.Anchor()
}

// Anchor returns the mapping of the module block, which points at the
// terraform.source attribute of the unit.
func (t LineTable) Anchor() (LineMapping, bool) {
	if len(t) == 0 || t[0].Argument != "" {
		return LineMapping{}, false
	}
	return t[0], true
}

// TerragruntTranslation is the Terraform a Terragrunt unit means: a module
// call with the unit's source and values, served as a virtual file next to
// the unit file. Positions in Text map to the real files through Lines.
type TerragruntTranslation struct {
	// FileName is the base name of the virtual file, in the unit's directory.
	FileName string
	// Text is the translation, as Terraform configuration.
	Text string
	// Lines maps each virtual line of Text to its real position.
	Lines LineTable
}
