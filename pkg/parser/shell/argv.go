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
	commandFlag      = "-c"
	shellOptionValue = "-o"
)

var (
	shellValueOptions = map[string]bool{
		shellOptionValue: true, "+o": true, "-O": true, "+O": true, "--rcfile": true, "--init-file": true,
	}
	suValueOptions = map[string]bool{
		"-s": true, "--shell": true, "-g": true, "--group": true,
		"-G": true, "--supp-group": true, "-w": true, "--whitelist-environment": true,
	}
)

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
		if i+1 < len(words) {
			if consumesShellOptionValue(opt) {
				i++
				applyShellOptionValue(&res.options, opt, words[i])
			} else if shellValueOptions[opt] {
				i++
			}
		}
	}
	return res
}

func isShellOptionToken(opt string) bool {
	return strings.HasPrefix(opt, "-") || strings.HasPrefix(opt, "+")
}

func consumesShellOptionValue(opt string) bool {
	return !strings.HasPrefix(opt, optionEnd) && strings.HasSuffix(opt, "o")
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
		if !strings.ContainsRune("abcefhiklmnprstuvxBCEHPT", letter) {
			return false
		}
	}
	return true
}

func suScriptIndex(words []Value) (scriptIndex int, unknownOption bool) {
	var operands []int
	for i := 1; i < len(words); i++ {
		if !words[i].Known {
			return -1, true
		}
		arg := words[i].Text
		if arg == optionEnd {
			for j := i + 1; j < len(words); j++ {
				operands = append(operands, j)
			}
			break
		}
		if arg == commandFlag || arg == "--command" || isSuBundledCommandFlag(arg) {
			if i+1 < len(words) {
				return i + 1, false
			}
			return -1, false
		}
		if suValueOptions[arg] {
			i++
			continue
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			continue
		}
		operands = append(operands, i)
	}
	return suForwardedScriptIndex(words, operands)
}

func isSuBundledCommandFlag(arg string) bool {
	return len(arg) > 2 && strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, optionEnd) &&
		strings.HasSuffix(arg, "c") && strings.Trim(arg[1:len(arg)-1], "lmpPf") == ""
}

// suForwardedScriptIndex resolves shell -c arguments forwarded after su's
// optional login marker (`-`) and username operand.
func suForwardedScriptIndex(words []Value, operands []int) (scriptIndex int, unknownOption bool) {
	if len(operands) > 0 && words[operands[0]].Known && words[operands[0]].Text == "-" {
		operands = operands[1:]
	}
	if len(operands) < 2 {
		return -1, false
	}
	forwarded := make([]Value, 1, len(operands))
	forwarded[0] = Value{Text: sh, Known: true}
	for _, idx := range operands[1:] {
		forwarded = append(forwarded, words[idx])
	}
	parsed := parseShellArgv(shellOptions{shell: sh, known: true}, forwarded)
	if parsed.scriptIndex < 1 || parsed.scriptIndex >= len(forwarded) {
		return -1, parsed.unknownOption
	}
	return operands[parsed.scriptIndex], parsed.unknownOption
}
