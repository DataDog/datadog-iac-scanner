/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package shell

import (
	"path"
	"strings"
)

const (
	sudoCommand    = "sudo"
	envCommand     = "env"
	execCommand    = "exec"
	commandBuiltin = "command"
	chrootCommand  = "chroot"
	xargsCommand   = "xargs"
)

type wrapperSpec struct {
	operands  int
	values    map[string]bool
	flags     string
	longFlags map[string]bool
}

func wrapper(operands int, valueOptions, flags, longFlags string) wrapperSpec {
	spec := wrapperSpec{operands: operands, values: map[string]bool{}, flags: flags, longFlags: map[string]bool{}}
	for _, option := range strings.Fields(valueOptions) {
		spec.values[option] = true
	}
	for _, option := range strings.Fields(longFlags) {
		spec.longFlags[option] = true
	}
	return spec
}

var wrappers = map[string]wrapperSpec{
	sudoCommand:    wrapper(0, "u user g group h host p prompt C close-from D chdir R chroot", "nEHSkb", "non-interactive preserve-env"),
	envCommand:     wrapper(0, "u unset C chdir argv0", "i0v", "ignore-environment null"),
	execCommand:    wrapper(0, "a", "cl", ""),
	commandBuiltin: wrapper(0, "", "p", ""),
	"time":         wrapper(0, "f format o output", "pav", "portability append verbose"),
	"nohup":        {},
	"setsid":       wrapper(0, "", "cfw", "ctty fork wait"),
	"nice":         wrapper(0, "n adjustment", "", ""),
	"timeout":      wrapper(1, "s signal k kill-after", "v", "foreground preserve-status verbose"),
	"gosu":         {operands: 1},
	"su-exec":      {operands: 1},
	chrootCommand:  wrapper(1, "userspec groups", "", "skip-chdir"),
	xargsCommand: wrapper(0,
		"a arg-file d delimiter E I L max-lines n max-args P max-procs s max-chars",
		"0rptx", "null no-run-if-empty verbose"),
}

func unwrap(values []Value, shellForm bool) ([]Value, []string, bool) {
	chain := []string{}
	for len(values) > 0 && values[0].Known {
		name := path.Base(values[0].Text)
		spec, found := wrappers[name]
		if !found || (!shellForm && (name == execCommand || name == commandBuiltin)) {
			break
		}
		start, ok := wrapperStart(values, name, spec)
		if !ok {
			return nil, nil, false
		}
		if start == 0 {
			break
		}
		chain = append(chain, name)
		values = values[start:]
	}
	return values, chain, len(values) > 0
}

func wrapperStart(values []Value, name string, spec wrapperSpec) (int, bool) {
	i := 1
	for i < len(values) {
		if !values[i].Known {
			return 0, false
		}
		arg := values[i].Text
		if name == commandBuiltin && strings.ContainsAny(strings.TrimPrefix(arg, "-"), "vV") && strings.HasPrefix(arg, "-") {
			return 0, true
		}
		if arg == optionEnd {
			i++
			break
		}
		if (name == envCommand || name == sudoCommand) && !strings.HasPrefix(arg, "-") && strings.Contains(arg, "=") {
			i++
			continue
		}
		if !strings.HasPrefix(arg, "-") {
			break
		}
		consumed, ok := wrapperOption(arg, spec)
		if !ok {
			return 0, false
		}
		i += consumed
	}
	i += spec.operands
	return i, i < len(values)
}

func wrapperOption(arg string, spec wrapperSpec) (int, bool) {
	if strings.HasPrefix(arg, optionEnd) {
		option, _, attached := strings.Cut(strings.TrimPrefix(arg, optionEnd), "=")
		if spec.values[option] {
			if attached {
				return 1, true
			}
			return 2, true
		}
		return 1, spec.longFlags[option] && !attached
	}
	short := strings.TrimPrefix(arg, "-")
	for i, r := range short {
		if spec.values[string(r)] {
			if i+1 < len(short) {
				return 1, true
			}
			return 2, true
		}
		if !strings.ContainsRune(spec.flags, r) {
			return 0, false
		}
	}
	return 1, short != ""
}
