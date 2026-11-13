package shell

import (
	"regexp"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// PackageCommand is a package manager call read with that manager's
// command-line grammar, so rules never separate options from operands.
type PackageCommand struct {
	Call       int           `json:"call"`
	Manager    string        `json:"manager"`
	Subcommand string        `json:"subcommand"`
	Action     string        `json:"action"`
	Options    []Option      `json:"options"`
	Packages   []Package     `json:"packages"`
	AssumeYes  bool          `json:"assume_yes"`
	Known      bool          `json:"known"`
	Source     *model.Source `json:"source,omitempty"`
}

// Option is an option as written; Value holds its argument, attached or not.
type Option struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

// Package is an operand naming a package from the manager's registry.
type Package struct {
	Name     string        `json:"name"`
	Pinned   bool          `json:"pinned"`
	Source   *model.Source `json:"source,omitempty"`
	Argument int           `json:"-"`
}

type managerGrammar struct {
	actions map[string]string
	values  map[string]bool
	operand func(token string) bool
	pinned  func(arguments []Value, index int, options []Option) bool
	yes     func(options []Option) bool
	// editable marks pip, whose -e/--editable value can be a VCS URL to install.
	editable bool
}

const pip = "pip"

var (
	versionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`[A-Za-z0-9_+-]+[-:]\$.+`),
		regexp.MustCompile(`[A-Za-z0-9_+-]+[:-](\d+.)+\d+`),
		regexp.MustCompile(`[A-Za-z0-9_+-]+~?=.+`),
	}
	nonRegistryNodePackage = regexp.MustCompile(`^(git|-|\./|\.\./|/|file:|link:|workspace:|github:)`)
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

func versioned(arguments []Value, index int, _ []Option) bool {
	for _, pattern := range versionPatterns {
		if pattern.MatchString(arguments[index].Text) {
			return true
		}
	}
	return false
}

func registryName(token string) bool {
	return token != "" && (token[0] >= 'a' && token[0] <= 'z' || token[0] >= 'A' && token[0] <= 'Z')
}

func hasOption(options []Option, names ...string) bool {
	for _, option := range options {
		for _, name := range names {
			if option.Name == name {
				return true
			}
		}
	}
	return false
}

func bundles(options []Option, letter string) bool {
	for _, option := range options {
		short := strings.TrimPrefix(option.Name, "-")
		if !strings.HasPrefix(option.Name, "--") && short != option.Name && strings.Contains(short, letter) && option.Value == "" {
			return true
		}
	}
	return false
}

func aptAssumeYes(options []Option) bool {
	quiet := 0
	for _, option := range options {
		switch {
		case option.Name == "-qq" || option.Name == "-q=2":
			quiet += 2
		case option.Name == "-q" || option.Name == "--quiet":
			quiet++
			if option.Value == "2" {
				quiet++
			}
		case (option.Name == "-o" || option.Name == "--option") && strings.EqualFold(option.Value, "APT::Get::Assume-Yes=true"):
			return true
		}
	}
	return quiet >= 2 || hasOption(options, "--yes", "--assume-yes") || bundles(options, "y")
}

func rpmAssumeYes(options []Option) bool {
	return hasOption(options, "--assumeyes", "--assume-yes", "--yes", "-yes") || bundles(options, "y")
}

func zypperAssumeYes(options []Option) bool {
	return hasOption(options, "-y", "--no-confirm", "--non-interactive", "-n")
}

func never([]Option) bool { return false }

func nodePackage(token string) bool {
	return token != "" && !nonRegistryNodePackage.MatchString(token)
}

func nodePinned(arguments []Value, index int, _ []Option) bool {
	name := arguments[index].Text
	if strings.HasPrefix(name, "@") {
		_, name, _ = strings.Cut(name, "/")
	}
	return strings.Contains(name, "@")
}

// gemPinned accepts a version given right after the gem it applies to.
func gemPinned(arguments []Value, index int, options []Option) bool {
	if versioned(arguments, index, options) {
		return true
	}
	return index+1 < len(arguments) && (arguments[index+1].Text == "-v" || arguments[index+1].Text == "--version")
}

const nodeValues = "--registry --userconfig --globalconfig --cache --prefix -C --tag --proxy --https-proxy --noproxy " +
	"--cafile --ca --cert --key --loglevel --logs-dir --fetch-retries --fetch-retry-factor --fetch-retry-mintimeout " +
	"--fetch-retry-maxtimeout --fetch-timeout --maxsockets --install-strategy --script-shell --node-options --user-agent --before "

const rpmValues = "--enablerepo --disablerepo --repo --repoid --repofrompath --releasever --setopt --installroot -c --config " +
	"--exclude -x --disableexcludes --enableplugin --disableplugin --downloaddir --destdir --advisory --bz --cve " +
	"--security-severity --forcearch --comment -d --debuglevel -e --errorlevel"

var (
	aptGrammar = &managerGrammar{
		actions: map[string]string{
			"reinstall": "install", "purge": "remove", "autoremove": "remove",
			"dist-upgrade": "upgrade", "full-upgrade": "upgrade", "autoclean": "clean",
		},
		values:  set("-o --option -c --config-file -t --target-release"),
		operand: registryName, pinned: versioned, yes: aptAssumeYes,
	}
	rpmGrammar = &managerGrammar{
		actions: map[string]string{
			"in": "install", "rei": "install", "reinstall": "install", "groupinstall": "install", "localinstall": "install",
			"install-n": "install", "install-na": "install", "install-nevra": "install", "erase": "remove", "rm": "remove",
		},
		values:  set(rpmValues),
		operand: registryName, pinned: versioned, yes: rpmAssumeYes,
	}
	grammars = map[string]*managerGrammar{
		"apt-get": aptGrammar, "apt": aptGrammar, "aptitude": aptGrammar,
		"apk": {
			actions: map[string]string{"add": "install", "del": "remove"},
			values:  set("--virtual -t --repository -X --root -p --arch --keys-dir --cache-dir"),
			operand: registryName, pinned: versioned, yes: never,
		},
		"yum": rpmGrammar, "dnf": rpmGrammar, "microdnf": rpmGrammar, "tdnf": rpmGrammar,
		"zypper": {
			actions: map[string]string{
				"in": "install", "si": "install", "source-install": "install", "rm": "remove",
				"ref": "refresh", "up": "update", "cc": "clean",
			},
			values: set("--repo -r --root -R --releasever --from --config -c --reposd-dir --cache-dir --raw-cache-dir " +
				"--solv-cache-dir --pkg-cache-dir --type -t --userdata --plus-repo --download --download-dir --solver-focus"),
			operand: registryName, pinned: versioned, yes: zypperAssumeYes,
		},
		pip: {
			values: set("--index-url -i --extra-index-url --find-links -f --trusted-host --target -t --platform " +
				"--python-version --python --implementation --abi --prefix --root --root-user-action --src --no-binary " +
				"--only-binary --proxy --cert --client-cert --cache-dir --log --exists-action --report -r -c --requirement " +
				"--constraint --upgrade-strategy --progress-bar --config-settings -C --global-option --group " +
				"--keyring-provider --use-feature --use-deprecated --build-constraint --requirements-from-script -e --editable"),
			operand: registryName, pinned: versioned, yes: never, editable: true,
		},
		"npm": {
			actions: map[string]string{"i": "install", "add": "install"},
			values:  set(nodeValues + "--workspace -w"),
			operand: nodePackage, pinned: nodePinned, yes: never,
		},
		"pnpm": {
			actions: map[string]string{"i": "install", "add": "install"},
			values: set(nodeValues + "--filter -F --filter-prod --dir --lockfile-dir --modules-dir --store-dir " +
				"--virtual-store-dir --hoist-pattern --public-hoist-pattern --changed-files-ignore-pattern --test-pattern " +
				"--child-concurrency --network-concurrency --workspace-concurrency --trust-policy-ignore-after --reporter"),
			operand: nodePackage, pinned: nodePinned, yes: never,
		},
		"yarn": {
			actions: map[string]string{"add": "install"},
			values:  set(nodeValues + "--cache-folder --cwd --modules-folder --network-timeout --mutex"),
			operand: nodePackage, pinned: nodePinned, yes: never,
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
		for i := 0; i+1 < len(call.Arguments); i++ {
			if call.Arguments[i].Text == "-m" && pipExecutable.MatchString(call.Arguments[i+1].Text) {
				return pip, i + 2
			}
		}
	}
	return call.Name, 0
}

func (grammar *managerGrammar) read(arguments []Value, offset int) PackageCommand {
	command := PackageCommand{Options: []Option{}, Packages: []Package{}, Known: true}
	operands := grammar.readOptions(&command, arguments, offset)
	if len(operands) == 0 {
		return command
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
			}
			break
		}
		if !strings.HasPrefix(token, "-") || token == "-" {
			operands = append(operands, i)
			continue
		}
		option, consumes := grammar.option(token)
		if consumes && i+1 < len(arguments) {
			i++
			option.Value = arguments[i].Text
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
