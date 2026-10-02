/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package analyzer

import (
	"bytes"
	"strings"
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

// iniSectionName returns the name inside a "[name]" header line.
func iniSectionName(line string) (string, bool) {
	if !strings.HasPrefix(line, "[") || !strings.HasSuffix(line, "]") {
		return "", false
	}
	return strings.TrimSpace(line[1 : len(line)-1]), true
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
		return true
	})
	return found
}

// looksLikeAnsibleInventory reports whether a .ini file is an INI inventory.
// Outside [group:vars] sections every entry starts with a host or group name,
// which never contains "="; app config (pytest.ini, mypy.ini, dev.ini) is made
// of "key=value" or "key = value" entries instead.
func looksLikeAnsibleInventory(content []byte) bool {
	inVars := false
	entries := 0
	ok := true
	iniLines(content, func(line string) bool {
		if name, isSection := iniSectionName(line); isSection {
			inVars = strings.HasSuffix(name, ":vars")
			return true
		}
		if inVars {
			return true
		}
		fields := strings.Fields(line)
		if strings.Contains(fields[0], "=") || (len(fields) > 1 && strings.HasPrefix(fields[1], "=")) {
			ok = false
			return false
		}
		entries++
		return true
	})
	return ok && entries > 0
}
