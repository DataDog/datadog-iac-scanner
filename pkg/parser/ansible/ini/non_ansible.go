package ini

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/shlex"
)

// IsKnownNonAnsible rejects only recognizable unrelated formats, not generic
// key=value configuration: those lines can also be malformed inventories.
// Keep this gate in the parsers so disk, pushed-content and direct callers agree.
func IsKnownNonAnsible(content []byte, filename string) bool {
	base := filepath.Base(filename)
	if base == "ansible.cfg" || strings.Contains(string(content), "ansible_") {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(filepath.Clean(filename)), "/") {
		switch part {
		case "ansible", "inventory", "inventories", "host_vars", "group_vars":
			return false
		}
	}
	lines := strings.Split(string(content), "\n")
	if base == "pytest.ini" {
		return isPytestConfig(lines)
	}
	return filepath.Ext(filename) == ".cfg" && isTLAModelConfig(lines)
}

// Both the canonical name and a single [pytest] section are required. Host
// declarations and inventory sections veto the skip. Do not shell-tokenize
// pytest values: regexes and warning text need not contain balanced quotes.
func isPytestConfig(lines []string) bool {
	section, assignment, warningFilters := false, false, false
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if !section {
			if line != "[pytest]" {
				return false
			}
			section = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			return false
		}
		key, _, found := strings.Cut(line, "=")
		if found && len(strings.Fields(key)) == 1 {
			assignment = true
			warningFilters = strings.TrimSpace(key) == "filterwarnings"
			continue
		}
		if !warningFilters || (raw[0] != ' ' && raw[0] != '\t') || !isPytestWarningFilter(line) {
			return false
		}
	}
	return section && assignment
}

// Other indented continuations are ambiguous with actual inventory hosts. Only
// recognizable warning filters may bypass inventory parsing (not bare hostnames
// or host declarations with variables), even under the canonical pytest name.
func isPytestWarningFilter(line string) bool {
	action, filter, found := strings.Cut(line, ":")
	if !found {
		return false
	}
	// Require message:category, not just an action prefix. Numeric port
	// suffixes on the first token remain inventory evidence even if a later
	// host variable happens to contain another colon.
	_, category, found := strings.Cut(filter, ":")
	if !found || strings.TrimSpace(category) == "" {
		return false
	}
	// Match aini's quoting/escaping for the first token only. The remaining
	// pytest warning text may contain unmatched quotes and is not shell syntax.
	if host, err := shlex.NewLexer(strings.NewReader(line)).Next(); err == nil {
		hostParts := strings.Split(host, ":")
		if _, err := strconv.Atoi(hostParts[len(hostParts)-1]); err == nil {
			return false
		}
	}
	switch action {
	case "error", "ignore", "always", "default", "module", "once":
		return true
	}
	return false
}

// TLC model configs have no INI sections. Require a constants preamble, a
// substitution and a model directive together, rather than discarding arbitrary
// malformed headerless CFG files.
func isTLAModelConfig(lines []string) bool {
	started, substitution, directive := false, false, false
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "\\*") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			return false
		}
		fields := strings.Fields(line)
		if !started {
			if fields[0] != "CONSTANTS" && fields[0] != "CONSTANT" {
				return false
			}
			started = true
		}
		if len(fields) == 3 && fields[1] == "<-" {
			substitution = true
		}
		if len(fields) == 2 {
			switch fields[0] {
			case "SPECIFICATION", "INVARIANT", "PROPERTY":
				directive = true
			}
		}
	}
	return started && substitution && directive
}
