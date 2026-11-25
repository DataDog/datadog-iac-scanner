/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package shell

import (
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

const (
	bashShell        = "bash"
	sh               = "sh"
	ashShell         = "ash"
	dashShell        = "dash"
	kshShell         = "ksh"
	zshShell         = "zsh"
	suCommand        = "su"
	optionEnd        = "--"
	shellOptionValue = "-o"
)

var shellValueOptions = map[string]bool{
	shellOptionValue: true, "+o": true, "-O": true, "+O": true, "--rcfile": true, "--init-file": true,
}

type shellOptions struct {
	shell    string
	pipefail bool
	known    bool
}

type shellArgvResult struct {
	options       shellOptions
	scriptIndex   int
	unknownOption bool
}

type nestedShellScript struct {
	shellName     string
	options       shellOptions
	script        Value
	spanArgIndex  int
	found         bool
	unknownOption bool
}

// normalizeShell extracts the base executable name from a shell command string.
func normalizeShell(shell string) string {
	fields := strings.Fields(shell)
	if len(fields) == 0 {
		return ""
	}
	return path.Base(fields[0])
}

func shellLangVariant(shellName string) (syntax.LangVariant, bool) {
	switch normalizeShell(shellName) {
	case sh, ashShell, dashShell:
		return syntax.LangPOSIX, true
	case bashShell, zshShell:
		return syntax.LangBash, true
	case kshShell:
		return syntax.LangMirBSDKorn, true
	default:
		return 0, false
	}
}

func isScriptShell(name string) bool {
	_, ok := shellLangVariant(name)
	return ok
}

// parseShellArgv is the shared option/operand reader for shell invocations
// (`sh`, `bash`, `set`, etc.). It tracks `pipefail` state, locates any `-c`
// script operand, and reports whether an unknown option word prevented
// deterministic option parsing.
func parseShellArgv(initial shellOptions, words []Value) shellArgvResult {
	res := shellArgvResult{options: initial, scriptIndex: -1}
	hasCommand := false
	for i := 1; i < len(words); i++ {
		word := words[i]
		if !word.Known {
			res.options.known = false
			res.unknownOption = true
			if hasCommand {
				res.scriptIndex = i
			}
			return res
		}
		opt := word.Text
		if opt == optionEnd || opt == "-" {
			if hasCommand && i+1 < len(words) {
				res.scriptIndex = i + 1
			}
			return res
		}
		if !isShellOptionToken(opt) {
			if hasCommand {
				res.scriptIndex = i
			}
			return res
		}
		if commandOption(opt) {
			hasCommand = true
		}
		i = consumeShellOptionValues(&res.options, opt, words, i)
	}
	return res
}

func isShellOptionToken(opt string) bool {
	return strings.HasPrefix(opt, "-") || strings.HasPrefix(opt, "+")
}

func consumeShellOptionValues(state *shellOptions, opt string, words []Value, i int) int {
	if strings.HasPrefix(opt, optionEnd) {
		if shellValueOptions[opt] && i+1 < len(words) {
			return i + 1
		}
		return i
	}
	for _, r := range opt[1:] {
		if r != 'o' && r != 'O' {
			continue
		}
		if i+1 >= len(words) {
			break
		}
		i++
		if r == 'o' {
			applyShellOptionValue(state, opt, words[i])
		}
	}
	return i
}

func applyShellOptionValue(state *shellOptions, opt string, val Value) {
	if !val.Known {
		state.known = false
		return
	}
	if val.Text == "pipefail" {
		state.pipefail = strings.HasPrefix(opt, "-")
		state.known = true
	}
}

func commandOption(option string) bool {
	if !strings.HasPrefix(option, "-") || strings.HasPrefix(option, optionEnd) || !strings.Contains(option, "c") {
		return false
	}
	for _, letter := range option[1:] {
		if !strings.ContainsRune("abcefhiklmnoprstuvxBCEHOPT", letter) {
			return false
		}
	}
	return true
}

func resolveShellNestedScript(words []Value, name string) nestedShellScript {
	if name == suCommand {
		return parseSuArgv(words)
	}
	initial := shellOptions{shell: normalizeShell(name), known: true}
	parsed := parseShellArgv(initial, words)
	if parsed.scriptIndex < 1 || parsed.scriptIndex >= len(words) {
		return nestedShellScript{unknownOption: parsed.unknownOption}
	}
	return nestedShellScript{
		shellName:     name,
		options:       parsed.options,
		script:        words[parsed.scriptIndex],
		spanArgIndex:  parsed.scriptIndex - 1,
		found:         true,
		unknownOption: parsed.unknownOption,
	}
}

type suArgvState struct {
	selectedShell string
	hasCmd        bool
	cmdVal        Value
	cmdWordIdx    int
	operands      []int
	unknown       bool
}

func parseSuArgv(words []Value) nestedShellScript {
	st := suArgvState{selectedShell: sh}
	for i := 1; i < len(words); i++ {
		if !words[i].Known {
			st.unknown = true
			return nestedShellScript{unknownOption: true}
		}
		arg := words[i].Text
		if arg == optionEnd {
			for j := i + 1; j < len(words); j++ {
				st.operands = append(st.operands, j)
			}
			break
		}
		if strings.HasPrefix(arg, optionEnd) {
			i = st.parseLongOption(arg, words, i)
		} else if strings.HasPrefix(arg, "-") && arg != "-" {
			i = st.parseShortOptions(arg[1:], words, i)
		} else {
			st.operands = append(st.operands, i)
		}
		if st.unknown {
			return nestedShellScript{unknownOption: true}
		}
	}
	if st.hasCmd {
		return nestedShellScript{
			shellName:    st.selectedShell,
			options:      shellOptions{shell: normalizeShell(st.selectedShell), known: true},
			script:       st.cmdVal,
			spanArgIndex: st.cmdWordIdx - 1,
			found:        true,
		}
	}
	return suForwardedScript(words, st.operands, st.selectedShell)
}

func (st *suArgvState) parseLongOption(arg string, words []Value, i int) int {
	name, attachedVal, attached := strings.Cut(arg, "=")
	nextVal := func() (Value, int, bool) {
		if attached {
			return Value{Text: attachedVal, Known: true}, i, true
		}
		if i+1 < len(words) {
			i++
			return words[i], i, true
		}
		return Value{}, i, false
	}
	switch name {
	case "--command", "--session-command":
		if val, idx, ok := nextVal(); ok {
			st.hasCmd, st.cmdVal, st.cmdWordIdx = true, val, idx
		}
	case "--shell":
		if val, _, ok := nextVal(); ok {
			if !val.Known {
				st.unknown = true
			} else {
				st.selectedShell = val.Text
			}
		}
	case "--group", "--supp-group", "--whitelist-environment":
		if !attached && i+1 < len(words) {
			i++
		}
	}
	return i
}

func (st *suArgvState) parseShortOptions(flags string, words []Value, i int) int {
	for pos, r := range flags {
		rest := flags[pos+1:]
		nextVal := func() (Value, int, bool) {
			if rest != "" {
				return Value{Text: rest, Known: true}, i, true
			}
			if i+1 < len(words) {
				i++
				return words[i], i, true
			}
			return Value{}, i, false
		}
		switch r {
		case 'c':
			if val, idx, ok := nextVal(); ok {
				st.hasCmd, st.cmdVal, st.cmdWordIdx = true, val, idx
			}
			return i
		case 's':
			if val, _, ok := nextVal(); ok {
				if !val.Known {
					st.unknown = true
				} else {
					st.selectedShell = val.Text
				}
			}
			return i
		case 'g', 'G', 'w':
			if rest == "" && i+1 < len(words) {
				i++
			}
			return i
		}
	}
	return i
}

// suForwardedScript resolves shell -c arguments forwarded after su's
// optional login marker (`-`) and username operand.
func suForwardedScript(words []Value, operands []int, selectedShell string) nestedShellScript {
	if len(operands) > 0 && words[operands[0]].Known && words[operands[0]].Text == "-" {
		operands = operands[1:]
	}
	if len(operands) < 2 {
		return nestedShellScript{}
	}
	forwarded := make([]Value, 1, len(operands))
	forwarded[0] = Value{Text: selectedShell, Known: true}
	for _, idx := range operands[1:] {
		forwarded = append(forwarded, words[idx])
	}
	parsed := parseShellArgv(shellOptions{shell: normalizeShell(selectedShell), known: true}, forwarded)
	if parsed.scriptIndex < 1 || parsed.scriptIndex >= len(forwarded) {
		return nestedShellScript{unknownOption: parsed.unknownOption}
	}
	wordIdx := operands[parsed.scriptIndex]
	return nestedShellScript{
		shellName:     selectedShell,
		options:       parsed.options,
		script:        words[wordIdx],
		spanArgIndex:  wordIdx - 1,
		found:         true,
		unknownOption: parsed.unknownOption,
	}
}
