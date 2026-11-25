/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package shell

import (
	"regexp"
	"strings"
)

// PackageCommand is a package manager call read with that manager's
// command-line grammar, so rules never separate options from operands.
type PackageCommand struct {
	Call       int       `json:"call"`
	Manager    string    `json:"manager"`
	Subcommand string    `json:"subcommand"`
	Action     string    `json:"action"`
	Options    []Option  `json:"options"`
	Packages   []Package `json:"packages"`
	AssumeYes  bool      `json:"assume_yes"`
	Known      bool      `json:"known"`
}

// Option is an option as written; Value holds its argument, attached or not.
// Global reports whether the option appeared before the subcommand.
type Option struct {
	Name   string `json:"name"`
	Value  string `json:"value,omitempty"`
	Global bool   `json:"-"`
}

// Package is an operand naming a package from the manager's registry.
type Package struct {
	Name     string `json:"name"`
	Pinned   bool   `json:"pinned"`
	Argument int    `json:"-"`
	Span     Span   `json:"-"`
}

type managerGrammar struct {
	actions          map[string]string
	values           map[string]bool
	operand          func(token string) bool
	pinned           func(arguments []Value, index int, options []Option) bool
	yes              func(options []Option) bool
	globalSubcommand string
	// editable marks pip, whose -e/--editable value can be a VCS URL to install.
	editable bool
}

const (
	pip             = "pip"
	actionInstall   = "install"
	actionRemove    = "remove"
	actionUpgrade   = "upgrade"
	actionClean     = "clean"
	subcmdAdd       = "add"
	subcmdIn        = "in"
	subcmdReinstall = "reinstall"
	subcmdRm        = "rm"
	optYes          = "--yes"
	optAssumeYes    = "--assume-yes"
	optVersion      = "--version"
)

var (
	aptZypperVersionPattern = regexp.MustCompile(`^[A-Za-z0-9_.+-]+(:[A-Za-z0-9_-]+)?~?=.+$`)
	apkVersionPattern       = regexp.MustCompile(`^[A-Za-z0-9_.+-]+(~?=.+|~.+)$`)
	pipVersionPattern       = regexp.MustCompile(`^[A-Za-z0-9_.-]+(\[[^]]+\])?(===?|~=).+$`)
	rpmVersionPatterns      = []*regexp.Regexp{
		regexp.MustCompile(`^[A-Za-z0-9_.+-]+-(\d+:)?(\d+\.)+\d+[A-Za-z0-9.~+^]*(-\d[A-Za-z0-9_.~+^]*)?$`),
		regexp.MustCompile(`^[A-Za-z0-9_.+-]+-\d+:\d[A-Za-z0-9_.~+^]*(-\d[A-Za-z0-9_.~+^]*)?$`),
		regexp.MustCompile(`^[A-Za-z0-9_.+-]+-\d[A-Za-z0-9.~+^]*-\d[A-Za-z0-9_~+^]*\.[A-Za-z0-9_.]+$`),
		regexp.MustCompile(`^[A-Za-z0-9_.+-]+-\$.+$`),
		regexp.MustCompile(`^[A-Za-z0-9_.+-]+=.+$`),
	}
	gemVersionPattern      = regexp.MustCompile(`^[A-Za-z0-9_.-]+:(\d|\$).+`)
	nonRegistryNodePackage = regexp.MustCompile(`^(git(\+|:|@)|https?://|ssh://|-|\./|\.\./|/|file:|link:|workspace:|github:)`)
	pipExecutable          = regexp.MustCompile(`^pip[0-9.]*$`)
	pythonExecutable       = regexp.MustCompile(`^python[0-9.]*$`)
)

func set(words string) map[string]bool {
	result := map[string]bool{}
	for _, word := range strings.Fields(words) {
		result[word] = true
	}
	return result
}

func aptZypperPinned(arguments []Value, index int, _ []Option) bool {
	return aptZypperVersionPattern.MatchString(arguments[index].Text)
}

func apkPinned(arguments []Value, index int, _ []Option) bool {
	return apkVersionPattern.MatchString(arguments[index].Text)
}

func pipPinned(arguments []Value, index int, _ []Option) bool {
	return pipVersionPattern.MatchString(arguments[index].Text)
}

func rpmPinned(arguments []Value, index int, _ []Option) bool {
	text := arguments[index].Text
	for _, pattern := range rpmVersionPatterns {
		if pattern.MatchString(text) {
			return true
		}
	}
	return false
}

func registryName(token string) bool {
	return token != "" && (token[0] >= 'a' && token[0] <= 'z' || token[0] >= 'A' && token[0] <= 'Z' || token[0] >= '0' && token[0] <= '9')
}

func parseOptionBool(value string) (val, ok bool) {
	switch strings.ToLower(value) {
	case "", "true", "yes", "1":
		return true, true
	case "false", "no", "0":
		return false, true
	default:
		return false, false
	}
}

func aptQuietDelta(option Option) int {
	switch option.Name {
	case "-qq", "-q=2":
		return 2
	case "-q", "--quiet":
		if option.Value == "2" {
			return 2
		}
		return 1
	default:
		return 0
	}
}

func aptAssumeYesOption(option Option) (val, ok bool) {
	switch option.Name {
	case optYes, optAssumeYes:
		return parseOptionBool(option.Value)
	case "--no-yes", "--no-assume-yes":
		return false, true
	case "-o", "--option":
		key, raw, found := strings.Cut(option.Value, "=")
		if found && strings.EqualFold(key, "APT::Get::Assume-Yes") {
			return parseOptionBool(raw)
		}
	default:
		if !strings.HasPrefix(option.Name, "--") && strings.HasPrefix(option.Name, "-") &&
			option.Value == "" && strings.Contains(option.Name[1:], "y") {
			return true, true
		}
	}
	return false, false
}

func aptAssumeYes(options []Option) bool {
	quiet := 0
	assumeYes := false
	for _, option := range options {
		quiet += aptQuietDelta(option)
		if val, ok := aptAssumeYesOption(option); ok {
			assumeYes = val
		}
	}
	return assumeYes || quiet >= 2
}

func rpmAssumeYes(options []Option) bool {
	assumeYes := false
	for _, option := range options {
		switch option.Name {
		case "--assumeyes", optAssumeYes, optYes, "-yes":
			if val, ok := parseOptionBool(option.Value); ok {
				assumeYes = val
			}
		case "--assumeno":
			assumeYes = false
		case "--setopt":
			key, raw, found := strings.Cut(option.Value, "=")
			if found && strings.EqualFold(key, "assumeyes") {
				if val, ok := parseOptionBool(raw); ok {
					assumeYes = val
				}
			}
		default:
			if !strings.HasPrefix(option.Name, "--") && strings.HasPrefix(option.Name, "-") &&
				option.Value == "" && strings.Contains(option.Name[1:], "y") {
				assumeYes = true
			}
		}
	}
	return assumeYes
}

func zypperAssumeYes(options []Option) bool {
	assumeYes := false
	for _, option := range options {
		switch option.Name {
		case "-y", "--no-confirm", "--non-interactive":
			if val, ok := parseOptionBool(option.Value); ok {
				assumeYes = val
			}
		case "-n":
			// Before the subcommand, -n is --non-interactive; after the
			// subcommand, -n is --name (package-name matching).
			if option.Global {
				if val, ok := parseOptionBool(option.Value); ok {
					assumeYes = val
				}
			}
		}
	}
	return assumeYes
}

func never([]Option) bool { return false }

func nodePackage(token string) bool {
	name, _, _ := strings.Cut(token, "@")
	return token != "" && !strings.Contains(name, "/") && !nonRegistryNodePackage.MatchString(token)
}

func nodePinned(arguments []Value, index int, _ []Option) bool {
	name := arguments[index].Text
	if strings.HasPrefix(name, "@") {
		_, name, _ = strings.Cut(name, "/")
	}
	_, version, hasAt := strings.Cut(name, "@")
	return hasAt && version != ""
}

func isGemVersionFlag(token string) bool {
	return token == optVersion || strings.HasPrefix(token, optVersion+"=") || strings.HasPrefix(token, "-v")
}

// gemPinned accepts a version given inline (name:1.0), right after the gem it
// applies to (`gem install rails -v 7.0`), or as a leading version flag before
// the gem (`gem install -v 7.0 rails`).
func gemPinned(arguments []Value, index int, _ []Option) bool {
	if gemVersionPattern.MatchString(arguments[index].Text) {
		return true
	}
	if index+1 < len(arguments) && isGemVersionFlag(arguments[index+1].Text) {
		return true
	}
	// Check whether a leading -v/--version immediately precedes this gem
	// (with no earlier gem operand between it and this gem).
	if index >= 1 && isGemVersionFlag(arguments[index-1].Text) &&
		(strings.HasPrefix(arguments[index-1].Text, optVersion+"=") || len(arguments[index-1].Text) > 2) {
		return index < 2 || strings.HasPrefix(arguments[index-2].Text, "-") || arguments[index-2].Text == actionInstall
	}
	if index >= 2 && (arguments[index-2].Text == "-v" || arguments[index-2].Text == optVersion) {
		return index < 3 || strings.HasPrefix(arguments[index-3].Text, "-") || arguments[index-3].Text == actionInstall
	}
	return false
}

const nodeValues = "--registry --userconfig --globalconfig --cache --prefix -C --tag --proxy --https-proxy --noproxy " +
	"--cafile --ca --cert --key --loglevel --logs-dir --fetch-retries --fetch-retry-factor --fetch-retry-mintimeout " +
	"--fetch-retry-maxtimeout --fetch-timeout --maxsockets --install-strategy --script-shell --node-options --user-agent --before " +
	"--audit-level "

const rpmValues = "--enablerepo --disablerepo --repo --repoid --repofrompath --releasever --setopt --installroot -c --config " +
	"--exclude -x --disableexcludes --enableplugin --disableplugin --downloaddir --destdir --advisory --bz --cve " +
	"--security-severity --forcearch --comment -d --debuglevel -e --errorlevel"

var (
	aptGrammar = &managerGrammar{
		actions: map[string]string{
			subcmdReinstall: actionInstall, "purge": actionRemove, "autoremove": actionRemove,
			"dist-upgrade": actionUpgrade, "full-upgrade": actionUpgrade, "autoclean": actionClean,
		},
		values:  set("-o --option -c --config-file -t --target-release -a --host-architecture"),
		operand: registryName, pinned: aptZypperPinned, yes: aptAssumeYes,
	}
	rpmGrammar = &managerGrammar{
		actions: map[string]string{
			subcmdIn: actionInstall, "rei": actionInstall, subcmdReinstall: actionInstall,
			"groupinstall": actionInstall, "localinstall": actionInstall,
			"install-n": actionInstall, "install-na": actionInstall, "install-nevra": actionInstall,
			"erase": actionRemove, subcmdRm: actionRemove,
		},
		values:  set(rpmValues),
		operand: registryName, pinned: rpmPinned, yes: rpmAssumeYes,
	}
	grammars = map[string]*managerGrammar{
		"apt-get": aptGrammar, "apt": aptGrammar, "aptitude": aptGrammar,
		"apk": {
			actions: map[string]string{subcmdAdd: actionInstall, "del": actionRemove},
			values:  set("--virtual -t --repository -X --root -p --arch --keys-dir --cache-dir"),
			operand: registryName, pinned: apkPinned, yes: never,
		},
		"yum": rpmGrammar, "dnf": rpmGrammar, "microdnf": rpmGrammar, "tdnf": rpmGrammar,
		"zypper": {
			actions: map[string]string{
				subcmdIn: actionInstall, "si": actionInstall, "source-install": actionInstall, subcmdRm: actionRemove,
				"ref": "refresh", "up": "update", "cc": actionClean,
			},
			values: set("--repo -r --root -R --releasever --from --config -c --reposd-dir --cache-dir --raw-cache-dir " +
				"--solv-cache-dir --pkg-cache-dir --type -t --userdata -p --plus-repo --download --download-dir --solver-focus"),
			operand: registryName, pinned: aptZypperPinned, yes: zypperAssumeYes,
		},
		pip: {
			values: set("--index-url -i --extra-index-url --find-links -f --trusted-host --target -t --platform " +
				"--python-version --python --implementation --abi --prefix --root --root-user-action --src --no-binary " +
				"--only-binary --proxy --cert --client-cert --cache-dir --log --log-file --exists-action --report -r -c --requirement " +
				"--constraint --upgrade-strategy --progress-bar --config-settings -C --global-option --group " +
				"--keyring-provider --use-feature --use-deprecated --build-constraint --requirements-from-script " +
				"-e --editable --timeout --default-timeout --retries"),
			operand: registryName, pinned: pipPinned, yes: never, editable: true,
		},
		"npm": {
			actions: map[string]string{"i": actionInstall, subcmdAdd: actionInstall},
			values:  set(nodeValues + "--workspace -w --omit --include --location --os --cpu --libc"),
			operand: nodePackage, pinned: nodePinned, yes: never,
		},
		"pnpm": {
			actions: map[string]string{"i": actionInstall, subcmdAdd: actionInstall},
			values: set(nodeValues + "--filter -F --filter-prod --dir --lockfile-dir --modules-dir --store-dir " +
				"--virtual-store-dir --hoist-pattern --public-hoist-pattern --changed-files-ignore-pattern --test-pattern " +
				"--child-concurrency --network-concurrency --workspace-concurrency --trust-policy-ignore-after --reporter"),
			operand: nodePackage, pinned: nodePinned, yes: never,
		},
		"yarn": {
			actions:          map[string]string{subcmdAdd: actionInstall},
			values:           set(nodeValues + "--cache-folder --cwd --modules-folder --network-timeout --mutex"),
			operand:          nodePackage,
			pinned:           nodePinned,
			yes:              never,
			globalSubcommand: "global",
		},
		"gem": {
			values: set("--source -s --install-dir -i --bindir -n --build-root --platform --without --config-file " +
				"--file -g -v --version"),
			operand: registryName, pinned: gemPinned, yes: never,
		},
	}
)

func packageCommands(calls []Invocation) []PackageCommand {
	result := []PackageCommand{}
	for i := range calls {
		manager, offset := managerOf(&calls[i])
		grammar, ok := grammars[manager]
		if !ok || calls[i].Deferred || calls[i].Function {
			continue
		}
		command := grammar.read(calls[i].Arguments[offset:], offset)
		command.Call, command.Manager = i, manager
		command.Known = command.Known && !calls[i].DynamicArguments
		for j := range command.Packages {
			argIdx := command.Packages[j].Argument
			if argIdx >= 0 && argIdx < len(calls[i].ArgumentSpans) {
				command.Packages[j].Span = calls[i].ArgumentSpans[argIdx]
			} else {
				command.Packages[j].Span = calls[i].Span
			}
		}
		result = append(result, command)
	}
	return result
}

// managerOf names the package manager a call runs and the index of the first
// argument it receives, which is not 0 for `python -m pip`.
func managerOf(call *Invocation) (manager string, offset int) {
	if pipExecutable.MatchString(call.Name) {
		return pip, 0
	}
	if pythonExecutable.MatchString(call.Name) {
		if offset, ok := pythonPipOffset(call.Arguments); ok {
			return pip, offset
		}
	}
	return call.Name, 0
}

func pythonPipOffset(args []Value) (offset int, ok bool) {
	for i := 0; i < len(args); i++ {
		if !args[i].Known {
			return 0, false
		}
		text := args[i].Text
		if text == "-" || text == optionEnd || !strings.HasPrefix(text, "-") {
			return 0, false
		}
		if strings.HasPrefix(text, "--") {
			if text == "--check-hash-based-pycs" {
				i++
			}
			continue
		}
		offset, done, consumedNext := pythonShortOption(text[1:], args, i)
		if done {
			return offset, offset > 0
		}
		if consumedNext {
			i++
		}
	}
	return 0, false
}

func pythonShortOption(flags string, args []Value, index int) (offset int, done, consumedNext bool) {
	for pos, r := range flags {
		switch r {
		case 'm':
			if rest := flags[pos+1:]; rest != "" {
				if pipExecutable.MatchString(rest) {
					return index + 1, true, false
				}
				return 0, true, false
			}
			if index+1 < len(args) && args[index+1].Known && pipExecutable.MatchString(args[index+1].Text) {
				return index + 2, true, false
			}
			return 0, true, false
		case 'c':
			return 0, true, false
		case 'W', 'X':
			return 0, false, pos+1 == len(flags)
		}
	}
	return 0, false, false
}

func (grammar *managerGrammar) read(arguments []Value, offset int) PackageCommand {
	command := PackageCommand{Options: []Option{}, Packages: []Package{}, Known: true}
	operands := grammar.readOptions(&command, arguments, offset)
	if len(operands) == 0 {
		return command
	}
	if grammar.globalSubcommand != "" && arguments[operands[0]].Text == grammar.globalSubcommand && len(operands) >= 2 {
		operands = operands[1:]
	}
	command.Subcommand = arguments[operands[0]].Text
	command.Action = command.Subcommand
	if action, ok := grammar.actions[command.Subcommand]; ok {
		command.Action = action
	}
	for _, i := range operands[1:] {
		token := arguments[i].Text
		if grammar.operand(token) {
			command.Packages = append(command.Packages, Package{Name: token, Argument: offset + i})
		}
	}
	for i := range command.Packages {
		if !grammar.editable || !strings.Contains(command.Packages[i].Name, "://") {
			command.Packages[i].Pinned = grammar.pinned(arguments, command.Packages[i].Argument-offset, command.Options)
		}
	}
	command.AssumeYes = grammar.yes(command.Options)
	return command
}

// readOptions collects the options of a command and returns the indices of
// its operands.
func (grammar *managerGrammar) readOptions(command *PackageCommand, arguments []Value, offset int) []int {
	operands := []int{}
	for i := 0; i < len(arguments); i++ {
		argument := arguments[i]
		if !argument.Known {
			command.Known = false
			continue
		}
		token := argument.Text
		if token == optionEnd {
			for j := i + 1; j < len(arguments); j++ {
				operands = append(operands, j)
				if !arguments[j].Known {
					command.Known = false
				}
			}
			break
		}
		if !strings.HasPrefix(token, "-") || token == "-" {
			operands = append(operands, i)
			continue
		}
		option, consumes := grammar.option(token)
		option.Global = len(operands) == 0
		if consumes && i+1 < len(arguments) {
			i++
			option.Value = arguments[i].Text
			if !arguments[i].Known {
				command.Known = false
			}
		}
		if grammar.editableVCS(option) {
			command.Packages = append(command.Packages, Package{Name: option.Value, Argument: offset + i})
		}
		command.Options = append(command.Options, option)
	}
	return operands
}

// option splits an option token into its name and attached value, and reports
// whether the next argument is its value.
func (grammar *managerGrammar) option(token string) (Option, bool) {
	if name, value, attached := strings.Cut(token, "="); attached && strings.HasPrefix(token, "--") {
		return Option{Name: name, Value: value}, false
	}
	if grammar.values[token] {
		return Option{Name: token}, true
	}
	if !strings.HasPrefix(token, "--") && len(token) > 2 && grammar.values[token[:2]] {
		return Option{Name: token[:2], Value: strings.TrimPrefix(token[2:], "=")}, false
	}
	return Option{Name: token}, false
}

// editableVCS reports a pip editable install from a version control URL,
// which installs whatever revision the URL resolves to.
func (grammar *managerGrammar) editableVCS(option Option) bool {
	return grammar.editable && (option.Name == "-e" || option.Name == "--editable") &&
		strings.Contains(option.Value, "://")
}
