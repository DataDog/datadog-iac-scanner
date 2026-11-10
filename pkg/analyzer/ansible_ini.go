/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package analyzer

import (
	"bytes"
	"regexp"
	"strings"
	"unicode"

	"github.com/google/shlex"
)

// ansibleConfigSections are the section headers ansible.cfg defines.
var ansibleConfigSections = map[string]struct{}{
	"defaults":              {},
	"privilege_escalation":  {},
	"persistent_connection": {},
	"connection":            {},
	"colors":                {},
	"selinux":               {},
	"diff":                  {},
	"galaxy":                {},
	"inventory":             {},
	"netconf_connection":    {},
	"paramiko_connection":   {},
	"ssh_connection":        {},
	"jinja2":                {},
	"tags":                  {},
}

var ansibleConfigSectionPrefixes = []string{"galaxy_server.", "callback_", "inventory_plugin_"}

// ansibleConfigSectionSuffixes match plugin sections such as [sudo_become_plugin].
var ansibleConfigSectionSuffixes = []string{"_become_plugin"}

// iniSectionName returns the name inside a "[name]" header line. Like the
// config parser, it accepts an inline comment after the header.
func iniSectionName(line string) (string, bool) {
	end := strings.IndexByte(line, ']')
	if !strings.HasPrefix(line, "[") || end < 0 {
		return "", false
	}
	return strings.TrimSpace(line[1:end]), true
}

func iniLines(content []byte, fn func(line string) bool) {
	content = bytes.TrimPrefix(content, []byte("\xef\xbb\xbf"))
	for len(content) > 0 {
		var raw []byte
		if i := bytes.IndexByte(content, '\n'); i >= 0 {
			raw, content = content[:i], content[i+1:]
		} else {
			raw, content = content, nil
		}
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 || raw[0] == '#' || raw[0] == ';' {
			continue
		}
		if !fn(string(raw)) {
			return
		}
	}
}

// looksLikeAnsibleConfig reports whether a .cfg/.conf file declares at least one
// ansible.cfg section; setup.cfg, zoo.cfg, modd.conf and the like do not.
func looksLikeAnsibleConfig(content []byte) bool {
	found := false
	iniLines(content, func(line string) bool {
		name, ok := iniSectionName(line)
		if !ok {
			return true
		}
		if _, ok := ansibleConfigSections[name]; ok {
			found = true
			return false
		}
		for _, p := range ansibleConfigSectionPrefixes {
			if strings.HasPrefix(name, p) {
				found = true
				return false
			}
		}
		for _, suffix := range ansibleConfigSectionSuffixes {
			if strings.HasSuffix(name, suffix) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// inventorySection is Ansible's pattern for an INI inventory section header:
// a group name, then an optional :hosts, :children or :vars type.
var inventorySection = regexp.MustCompile(`^\[([^:\]\s]+)(?::(\w+))?\]\s*(?:#.*)?$`)

// inventoryEntries checks the entries of a section by section type; a section
// without a type, like the lines before the first section, lists hosts.
var inventoryEntries = map[string]func(line string) bool{
	"":         isInventoryHostLine,
	"hosts":    isInventoryHostLine,
	"children": isInventoryGroupLine,
	"vars":     func(line string) bool { return strings.Contains(line, "=") },
}

// looksLikeAnsibleInventory reports whether a .ini file follows the INI
// inventory syntax Ansible accepts. A host line is a host pattern followed by
// key=value variables, a [group:children] entry is a group name and a
// [group:vars] entry is key=value. App config (pytest.ini, mypy.ini, dev.ini)
// is made of "key=value" or "key = value" entries; delimited data
// ("Name|Value"), "name: url" lists and "key value" entries are not host lines
// either. A [group:vars] section with entries is inventory evidence on its own.
func looksLikeAnsibleInventory(content []byte) bool {
	isEntry := isInventoryHostLine
	entries := 0
	ok := true
	iniLines(content, func(line string) bool {
		if strings.HasPrefix(line, "[") {
			if m := inventorySection.FindStringSubmatch(line); m != nil {
				isEntry, ok = inventoryEntries[m[2]]
				return ok
			}
			if strings.HasSuffix(line, "]") {
				ok = false
				return false
			}
		}
		ok = isEntry(line)
		entries++
		return ok
	})
	return ok && entries > 0
}

// isInventoryHostLine reports whether line is a host pattern followed by
// key=value variables, split with shell quoting and "#" comments.
func isInventoryHostLine(line string) bool {
	fields, err := shlex.Split(line)
	if err != nil || len(fields) == 0 || !isHostPattern(fields[0]) {
		return false
	}
	for _, f := range fields[1:] {
		if strings.IndexByte(f, '=') < 1 {
			return false
		}
	}
	return true
}

// isInventoryGroupLine reports whether line names a single child group.
func isInventoryGroupLine(line string) bool {
	fields, err := shlex.Split(line)
	return err == nil && len(fields) == 1 && !strings.ContainsAny(fields[0], ":]")
}

// isHostPattern reports whether s is a hostname or an IPv4/IPv6 address,
// possibly with [x:y] ranges and a :port. These only use letters, digits and
// ".-_:[]", ranges do not nest, and what follows the last colon outside a range
// is a port number.
func isHostPattern(s string) bool {
	depth := 0
	for _, r := range s {
		switch r {
		case '[':
			depth++
		case ']':
			depth--
		default:
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune(".-_:", r) {
				return false
			}
		}
		if depth < 0 || depth > 1 {
			return false
		}
	}
	if depth != 0 {
		return false
	}
	i := strings.LastIndexByte(s, ':')
	if i < 0 || strings.Contains(s[i:], "]") {
		return true
	}
	port := s[i+1:]
	return port != "" && strings.Trim(port, "0123456789") == ""
}
