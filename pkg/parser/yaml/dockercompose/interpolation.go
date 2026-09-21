/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package dockercompose

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// interpolateNode applies Compose interpolation to every string scalar value
// in place. Keys are left untouched: rewriting them could produce
// duplicate-key documents.
func interpolateNode(node *yaml.Node, lookup func(name string) (string, bool)) {
	if node == nil {
		return
	}
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Tag == "!!str" && strings.ContainsRune(node.Value, '$') {
			node.Value = Interpolate(node.Value, lookup)
		}
	case yaml.MappingNode, yaml.SequenceNode, yaml.DocumentNode, yaml.AliasNode:
		for _, child := range node.Content {
			interpolateNode(child, lookup)
		}
	}
}

// Interpolate expands Compose-spec variable references in s using lookup:
//
//	$$              literal $
//	${VAR} / $VAR   value; left in place when unset
//	${VAR:-word}    word when VAR is unset or empty
//	${VAR-word}     word when VAR is unset
//	${VAR:?word}    required; left in place when unset
//	${VAR?word}     required when unset; left in place when unset
//	${VAR:+word}    word when VAR is set and non-empty; left in place when unset
//	${VAR+word}     word when VAR is set; left in place when unset
//
// Unresolvable references stay in the text: collapsing them to empty would
// fabricate findings (untagged `image: ${IMAGE}`) and hide others (the word
// in a `:+` default), so rules see the original expression as before.
func Interpolate(s string, lookup func(name string) (string, bool)) string {
	if !strings.ContainsRune(s, '$') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		c := s[i]
		if c != '$' {
			b.WriteByte(c)
			i++
			continue
		}
		if i+1 < len(s) && s[i+1] == '$' {
			// $$ is an escaped literal dollar.
			b.WriteByte('$')
			i += 2
			continue
		}
		if i+1 < len(s) && s[i+1] == '{' {
			end := matchingBrace(s, i)
			if end > i {
				if out, ok := applyExpr(s[i+2:end], lookup); ok {
					b.WriteString(out)
				} else {
					// Unresolvable reference: keep the original text.
					b.WriteString(s[i : end+1])
				}
				i = end + 1
				continue
			}
			// Unterminated ${...: leave the rest as-is.
			b.WriteString(s[i:])
			return b.String()
		}
		j := i + 1
		for j < len(s) && isNameChar(s[j]) {
			j++
		}
		if j == i+1 {
			// Lone '$' or '$' followed by a non-name character.
			b.WriteByte(c)
			i++
			continue
		}
		if v, ok := lookup(s[i+1 : j]); ok {
			b.WriteString(v)
		} else {
			// Bare $VAR with an unset variable: keep the reference.
			b.WriteString(s[i:j])
		}
		i = j
	}
	return b.String()
}

// matchingBrace returns the index of the '}' closing the "${" at s[open],
// tracking nested references; -1 when never closed.
func matchingBrace(s string, open int) int {
	depth := 0
	for j := open; j < len(s); j++ {
		switch {
		case s[j] == '$' && j+1 < len(s) && s[j+1] == '{':
			depth++
			j++
		case s[j] == '}':
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return -1
}

// applyExpr expands a ${...} reference body, e.g. "VAR:-nginx:latest".
// ok is false when the value is unknown and the reference must stay in
// place; chosen default/alternate words are interpolated recursively.
func applyExpr(expr string, lookup func(name string) (string, bool)) (string, bool) {
	k := 0
	for k < len(expr) && isNameChar(expr[k]) {
		k++
	}
	// lookupVar returns zero values for unset names, so a plain or required
	// reference reduces to (val, set).
	val, set := lookup(expr[:k])
	rest := expr[k:]
	switch {
	case rest == "":
		return val, set
	case strings.HasPrefix(rest, ":-"):
		if set && val != "" {
			return val, true
		}
		return Interpolate(rest[2:], lookup), true
	case strings.HasPrefix(rest, "-"):
		if set {
			return val, true
		}
		return Interpolate(rest[1:], lookup), true
	case strings.HasPrefix(rest, ":?"), strings.HasPrefix(rest, "?"):
		// Compose would fail the file on a missing required variable; the
		// scanner keeps the reference so rules still see it.
		return val, set
	case strings.HasPrefix(rest, ":+"):
		if set && val != "" {
			return Interpolate(rest[2:], lookup), true
		}
		return "", false
	case strings.HasPrefix(rest, "+"):
		if set {
			return Interpolate(rest[1:], lookup), true
		}
		return "", false
	default:
		// Malformed expression (e.g. "${VAR~x}"): leave it in place.
		return "", false
	}
}

func isNameChar(c byte) bool {
	return c == '_' ||
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9')
}
