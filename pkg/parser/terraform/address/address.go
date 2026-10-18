/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package address builds Terraform resource addresses that match the strings
// Terraform itself puts in a plan (resource_changes[].address): the module
// path, the resource mode, type and name, and one shared formatter for the
// instance keys count and for_each produce.
package address

import (
	"strings"

	"github.com/zclconf/go-cty/cty"
)

// Mode is the resource mode of an address. Ephemeral resources are listed for
// completeness; the scanner does not evaluate them today.
type Mode string

const (
	// ModeManaged is a resource block.
	ModeManaged Mode = "resource"
	// ModeData is a data block.
	ModeData Mode = "data"
	// ModeEphemeral is an ephemeral resource block.
	ModeEphemeral Mode = "ephemeral"
)

// prefix returns the address prefix a mode contributes: data blocks are
// addressed as data.<type>.<name>; managed and ephemeral blocks as <type>.<name>.
func (m Mode) prefix() string {
	if m == ModeData {
		return "data."
	}
	return ""
}

// FormatKey renders an instance key the way Terraform writes it in an
// address: an integral number as [N], a string as ["escaped"]. The escaping
// matches Terraform's addrs.InstanceKey.String: a backslash is doubled and a
// double quote is backslash-escaped; nothing else is escaped.
func FormatKey(key cty.Value) (string, bool) {
	if !key.IsKnown() || key.IsNull() {
		return "", false
	}
	switch {
	case key.Type() == cty.String:
		return `["` + EscapeKey(key.AsString()) + `"]`, true
	case key.Type() == cty.Number:
		bf := key.AsBigFloat()
		if bf.IsInt() {
			return "[" + bf.Text('f', -1) + "]", true
		}
		// Terraform only ever writes integer instance keys; a fractional
		// number cannot come from count or for_each, so render its decimal
		// form rather than inventing a format.
		return "[" + bf.Text('f', -1) + "]", true
	default:
		return "", false
	}
}

// EscapeKey escapes a for_each key for inclusion between double quotes in an
// address, matching Terraform: backslash first, then double quotes.
func EscapeKey(key string) string {
	if !strings.ContainsAny(key, `"\`) {
		return key
	}
	key = strings.ReplaceAll(key, `\`, `\\`)
	return strings.ReplaceAll(key, `"`, `\"`)
}

// ModuleSegment renders one module call hop: module.<name> with the call's
// instance key, if any.
func ModuleSegment(name string, key cty.Value) string {
	seg := "module." + name
	if formatted, ok := FormatKey(key); ok {
		seg += formatted
	}
	return seg
}

// Resource renders a resource address: the module path (already formatted as
// module segments joined by dots, empty at the root), the mode, type, name,
// and the instance key, if any.
func Resource(modulePath string, mode Mode, typ, name string, key cty.Value) string {
	var b strings.Builder
	if modulePath != "" {
		b.WriteString(modulePath)
		b.WriteByte('.')
	}
	b.WriteString(mode.prefix())
	b.WriteString(typ)
	b.WriteByte('.')
	b.WriteString(name)
	if formatted, ok := FormatKey(key); ok {
		b.WriteString(formatted)
	}
	return b.String()
}

// Unindexed renders the address of a block without meta-arguments (or whose
// expansion could not be resolved): the module path, mode, type and name with
// no instance key.
func Unindexed(modulePath string, mode Mode, typ, name string) string {
	var b strings.Builder
	if modulePath != "" {
		b.WriteString(modulePath)
		b.WriteByte('.')
	}
	b.WriteString(mode.prefix())
	b.WriteString(typ)
	b.WriteByte('.')
	b.WriteString(name)
	return b.String()
}
