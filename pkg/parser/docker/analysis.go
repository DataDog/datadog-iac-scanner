package docker

import (
	"path"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/shell"
	dockercommand "github.com/moby/buildkit/frontend/dockerfile/command"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

const (
	environmentBindings = "environment"
	argumentBindings    = "arguments"
	defaultShell        = "sh"
	envCommand          = "env"
	unknownInterpreter  = "__unsupported_interpreter__"
)

type Analysis struct {
	// ContractVersion describes the Dockerfile facts model consumed by Rego
	// rules. Rules declare the version they require in their package metadata.
	ContractVersion int `json:"contract_version"`
	// ResourceType and ResourceName identify the findings of rules using this
	// model, as the legacy rules name every Dockerfile.
	ResourceType    string         `json:"resource_type"`
	ResourceName    string         `json:"resource_name"`
	Instructions    []Instruction  `json:"instructions"`
	Stages          []Stage        `json:"stages"`
	StageNames      []string       `json:"stage_names"`
	Bindings        []BindingScope `json:"bindings"`
	GlobalArguments int            `json:"global_arguments"`
	Contexts        []Context      `json:"contexts"`
}

type Stage struct {
	Index            int           `json:"index"`
	Name             string        `json:"name"`
	BaseStage        int           `json:"base_stage"`
	OriginStage      int           `json:"origin_stage"`
	From             int           `json:"from"`
	Context          int           `json:"context"`
	InheritedOnbuild []int         `json:"inherited_onbuild,omitempty"`
	RunCommands      []shell.Value `json:"run_commands"`
	Source           model.Source  `json:"source"`
}

type Instruction struct {
	Index              int            `json:"index"`
	Kind               string         `json:"kind"`
	Flags              []Flag         `json:"flags,omitempty"`
	Healthcheck        *Healthcheck   `json:"healthcheck,omitempty"`
	Stage              int            `json:"stage"`
	FinalStage         bool           `json:"final_stage"`
	FirstOfKindInStage bool           `json:"first_of_kind_in_stage"`
	LastOfKindInStage  bool           `json:"last_of_kind_in_stage"`
	Source             model.Source   `json:"source"`
	Image              *Image         `json:"image,omitempty"`
	Platform           *shell.Value   `json:"platform,omitempty"`
	Copy               *Copy          `json:"copy,omitempty"`
	Bindings           []Binding      `json:"bindings,omitempty"`
	Value              *shell.Value   `json:"value,omitempty"`
	Values             []shell.Value  `json:"values,omitempty"`
	Ports              []Port         `json:"ports,omitempty"`
	Mounts             []Mount        `json:"mounts,omitempty"`
	Syntax             *CommandSyntax `json:"syntax,omitempty"`
	Execution          *Execution     `json:"execution,omitempty"`
	TriggerKind        string         `json:"trigger_kind,omitempty"`
	Trigger            *Instruction   `json:"trigger,omitempty"`
	Context            int            `json:"context"`
	ParseOK            bool           `json:"parse_ok"`
	Error              string         `json:"error,omitempty"`
}

// Execution is what an instruction runs, with the facts of its command line.
type Execution struct {
	Form               string       `json:"form"`
	Argv               []string     `json:"argv,omitempty"`
	Script             string       `json:"script,omitempty"`
	Shell              []string     `json:"shell,omitempty"`
	ShellKnown         bool         `json:"shell_known"`
	PackageCacheMounts []*BoolValue `json:"package_cache_mounts,omitempty"`
	*shell.Facts
}

type analysisState struct {
	result         *Analysis
	current        int
	currentShell   []string
	stageContexts  []Context
	stageShells    [][]string
	onbuildIndices map[int][]int
	invalidOnbuild map[int]bool
	context        Context
	contextIndex   int
	pending        []pendingTrigger
	// source locates the instruction being analyzed; it is nil for ONBUILD
	// triggers, whose text is not where they run.
	source *source
	node   *parser.Node
	escape rune
}

type pendingTrigger struct {
	index, stage int
	expression   string
}

func analyze(ast *parser.Node, src *source, escape rune) *Analysis {
	initialContext := Context{Environment: -1, Arguments: 0, UserInstruction: -1, Healthcheck: &Healthcheck{}}
	state := &analysisState{
		result: &Analysis{
			ContractVersion: ContractVersion,
			ResourceType:    dockerResource, ResourceName: dockerResource,
			Instructions: []Instruction{}, Stages: []Stage{},
			Bindings: []BindingScope{{Parent: -1, Kind: "build_arguments", Bindings: []Binding{}}},
			Contexts: []Context{cloneContext(&initialContext)},
		},
		current: -1, context: initialContext, source: src, escape: escape,
		onbuildIndices: make(map[int][]int), invalidOnbuild: make(map[int]bool),
	}
	for _, node := range ast.Children {
		state.instruction(node)
	}
	finalizeCopyStageRelations(state.result)
	state.finishTriggers()
	finalStage := len(state.result.Stages) - 1
	state.result.StageNames = make([]string, len(state.result.Stages))
	for i := range state.result.Stages {
		state.result.StageNames[i] = state.result.Stages[i].Name
	}
	for i := range state.result.Instructions {
		instruction := &state.result.Instructions[i]
		instruction.FinalStage = instruction.Stage >= 0 && instruction.Stage == finalStage
	}
	assignFirstOfKindInStage(state.result)
	assignLastOfKindInStage(state.result)
	assignStageRunCommands(state.result)
	assignInheritedOnbuildRunCommandUnknowns(state.result)
	return state.result
}

func (state *analysisState) instruction(node *parser.Node) {
	typed, err := instructions.ParseInstruction(node)
	state.node = node
	kind := strings.ToLower(node.Value)
	index := -1
	if !state.context.Deferred {
		index = len(state.result.Instructions)
	}
	entry := Instruction{Index: index, Kind: kind, ParseOK: err == nil, Source: state.source.instruction(node)}
	if kind == dockerFrom {
		state.beginStage(typed, entry.Source)
	}
	entry.Stage, entry.Context = state.current, state.contextIndex
	if kind == dockercommand.Onbuild && node.Next != nil && len(node.Next.Children) > 0 {
		entry.TriggerKind = strings.ToLower(node.Next.Children[0].Value)
	}
	for _, raw := range node.Flags {
		name, text, hasValue := strings.Cut(strings.TrimPrefix(raw, "--"), "=")
		if !hasValue {
			text = "true"
		}
		entry.Flags = append(entry.Flags, Flag{Name: name, Value: state.value(text)})
	}
	if err != nil {
		entry.Error = err.Error()
		if kind == dockercommand.From {
			entry.Image = &Image{Kind: unknownFact, Reference: shell.Value{}, Stage: -1}
		}
		state.invalidateFailedInstruction(kind, index)
	} else {
		state.enrich(&entry, typed)
		entry.Syntax = commandSyntaxFromExecution(entry.Execution)
	}
	state.snapshot()
	entry.Context = state.contextIndex
	state.result.Instructions = append(state.result.Instructions, entry)
	if kind == dockercommand.Onbuild {
		state.registerOnbuild(index, typed)
	}
	if state.current >= 0 {
		state.stageContexts[state.current] = state.context
		state.result.Stages[state.current].Context = state.contextIndex
	}
}

func (state *analysisState) registerOnbuild(index int, typed any) {
	if state.current < 0 || index < 0 {
		return
	}
	state.onbuildIndices[state.current] = append(state.onbuildIndices[state.current], index)
	command, ok := typed.(*instructions.OnbuildCommand)
	if !ok || command == nil {
		state.invalidOnbuild[index] = true
		return
	}
	parsed, parseErr := parser.Parse(strings.NewReader(command.Expression))
	if parseErr != nil || len(parsed.AST.Children) != 1 {
		state.invalidOnbuild[index] = true
		return
	}
	if _, triggerErr := instructions.ParseInstruction(parsed.AST.Children[0]); triggerErr != nil {
		state.invalidOnbuild[index] = true
	}
}

// CommandSyntax is the Dockerfile-authored form of an execution-bearing
// instruction. It remains independently available when semantic execution
// facts are unknown at policy evaluation time.
type CommandSyntax struct {
	Form   string   `json:"form"`
	Argv   []string `json:"argv,omitempty"`
	Script string   `json:"script,omitempty"`
}

func commandSyntaxFromExecution(execution *Execution) *CommandSyntax {
	if execution == nil {
		return nil
	}
	return &CommandSyntax{
		Form:   execution.Form,
		Argv:   append([]string(nil), execution.Argv...),
		Script: execution.Script,
	}
}

func (state *analysisState) beginStage(typed any, source model.Source) {
	state.current = len(state.result.Stages)
	state.currentShell = nil
	state.context = Context{Environment: -1, Arguments: -1, UserInstruction: -1, Healthcheck: &Healthcheck{}}
	stage := Stage{Index: state.current, From: len(state.result.Instructions), BaseStage: -1, OriginStage: state.current, Source: source}
	if command, ok := typed.(*instructions.Stage); ok && command != nil {
		stage.Name = command.Name
		base := state.image(command.BaseName, state.result.Stages)
		stage.BaseStage = base.Stage
		if base.Stage >= 0 {
			stage.OriginStage = state.result.Stages[base.Stage].OriginStage
			stage.InheritedOnbuild = append([]int(nil), state.onbuildIndices[base.Stage]...)
			state.currentShell = state.stageShells[base.Stage]
			state.context = cloneContext(&state.stageContexts[base.Stage])
			for _, triggerIndex := range stage.InheritedOnbuild {
				state.invalidateOnbuildConfig(triggerIndex)
			}
		}
	}
	state.context.Shell = append([]string(nil), state.currentShell...)
	state.context.ShellKnown = len(state.currentShell) > 0
	state.result.Stages = append(state.result.Stages, stage)
	state.stageShells = append(state.stageShells, state.currentShell)
	state.stageContexts = append(state.stageContexts, state.context)
	state.snapshot()
}

func (state *analysisState) enrich(entry *Instruction, typed any) {
	switch command := typed.(type) {
	case *instructions.Stage:
		entry.Image = state.imageFact(command.BaseName)
		entry.Platform = state.optionalValue(command.Platform)
	case *instructions.AddCommand, *instructions.CopyCommand:
		entry.Copy = state.copyFacts(command)
		state.copyStage(entry.Copy)
	case *instructions.RunCommand:
		state.run(entry, command)
	case *instructions.CmdCommand:
		entry.Execution = state.runtimeCommandSyntax(command.ShellDependantCmdLine)
	case *instructions.EntrypointCommand:
		entry.Execution = state.runtimeCommandSyntax(command.ShellDependantCmdLine)
	case *instructions.ShellCommand:
		state.currentShell = command.Shell
		if state.current >= 0 {
			state.stageShells[state.current] = command.Shell
		}
		state.context.Shell = append([]string(nil), command.Shell...)
		state.context.ShellKnown = len(command.Shell) > 0
		entry.Values = state.values(command.Shell)
	case *instructions.HealthCheckCommand:
		state.healthcheck(entry, command)
	case *instructions.OnbuildCommand:
		state.pending = append(state.pending, pendingTrigger{
			index: len(state.result.Instructions), stage: state.current, expression: command.Expression,
		})
	default:
		state.scalar(entry, typed)
	}
}

func (state *analysisState) scalar(entry *Instruction, typed any) {
	switch command := typed.(type) {
	case *instructions.UserCommand:
		v := state.declaredValue(command.User)
		entry.Value = &v
		state.context.User = v
		state.context.UserName = userName(&v)
		state.context.UserSet = true
		state.context.UserSetUnknown = false
		state.context.UserInstruction = len(state.result.Instructions)
		state.context.UserInstructionUnknown = state.context.Deferred
		if state.context.UserInstructionUnknown {
			state.context.UserInstruction = -1
		}
	case *instructions.WorkdirCommand:
		declared := state.declaredValue(command.Path)
		entry.Value = &declared
		v := declared
		if !path.IsAbs(v.Text) {
			if state.context.Workdir.Known && path.IsAbs(state.context.Workdir.Text) && v.Known {
				v.Text = path.Join(state.context.Workdir.Text, v.Text)
			} else {
				v.Known = false
			}
		}
		state.context.Workdir = v
	case *instructions.ExposeCommand:
		entry.Values = state.values(command.Ports)
		entry.Ports = exposePorts(entry.Values)
	case *instructions.VolumeCommand:
		entry.Values = state.values(command.Volumes)
	case *instructions.StopSignalCommand:
		v := state.value(command.Signal)
		entry.Value = &v
	case *instructions.MaintainerCommand:
		v := state.value(command.Maintainer)
		entry.Value = &v

	default:
		state.bindings(entry, typed)
	}
}

func (state *analysisState) bindings(entry *Instruction, typed any) {
	switch command := typed.(type) {
	case *instructions.EnvCommand:
		for _, binding := range command.Env {
			entry.Bindings = append(entry.Bindings, Binding{Name: binding.Key, Value: state.declaredValue(binding.Value), HasDefault: true})
		}
		state.bind(entry, environmentBindings)
	case *instructions.ArgCommand:
		for _, binding := range command.Args {
			fact := Binding{Name: binding.Key, HasDefault: binding.Value != nil}
			if binding.Value != nil {
				fact.Value = state.declaredValue(*binding.Value)
			}
			entry.Bindings = append(entry.Bindings, fact)
		}
		state.bind(entry, argumentBindings)
	case *instructions.LabelCommand:
		for _, binding := range command.Labels {
			entry.Bindings = append(entry.Bindings, Binding{Name: binding.Key, Value: state.declaredValue(binding.Value), HasDefault: true})
		}
	}
}

func (state *analysisState) values(raw []string) []shell.Value {
	result := make([]shell.Value, len(raw))
	for i, text := range raw {
		result[i] = state.value(text)
	}
	return result
}

func (state *analysisState) bind(entry *Instruction, kind string) {
	parent := state.context.Arguments
	if kind == environmentBindings {
		parent = state.context.Environment
	}
	id := len(state.result.Bindings)
	state.result.Bindings = append(state.result.Bindings, BindingScope{Parent: parent, Kind: kind, Bindings: entry.Bindings})
	if kind == environmentBindings {
		state.context.Environment = id
	} else {
		state.context.Arguments = id
		if state.current < 0 {
			state.result.GlobalArguments = id
		}
	}
}

func (state *analysisState) run(entry *Instruction, command *instructions.RunCommand) {
	if err := command.Expand(func(raw string) (string, error) { return raw, nil }); err != nil {
		entry.ParseOK = false
		entry.Error = err.Error()
	} else {
		for _, mount := range instructions.GetMounts(command) {
			entry.Mounts = append(entry.Mounts, Mount{
				Kind: string(mount.Type), Target: state.value(mount.Target), Source: state.value(mount.Source), From: state.optionalValue(mount.From),
				ReadOnly: mount.ReadOnly, CacheID: state.value(mount.CacheID), Sharing: string(mount.CacheSharing), Required: mount.Required,
			})
		}
	}
	entry.Execution = state.execution(command.ShellDependantCmdLine)
	entry.Execution.PackageCacheMounts = packageCacheMounts(entry.Execution, entry.Mounts, &state.context, entry.ParseOK)
}

// ONBUILD is evaluated downstream against the declaring image's final
// configuration. Its stage graph and build arguments belong to the child.
func (state *analysisState) finishTriggers() {
	prefixes := make(map[int]*analysisState)
	cursors := make(map[int]int)
	for _, pending := range state.pending {
		entry := &state.result.Instructions[pending.index]
		var prefix *analysisState
		var indices []int
		if pending.stage >= 0 {
			prefix = prefixes[pending.stage]
			if prefix == nil {
				inherited := cloneContext(&state.stageContexts[pending.stage])
				inherited.Arguments = -1
				inherited.Deferred = true
				prefix = &analysisState{
					result: state.result, context: inherited, current: -1,
					currentShell:   append([]string(nil), state.stageShells[pending.stage]...),
					invalidOnbuild: state.invalidOnbuild,
				}
				prefixes[pending.stage] = prefix
			}
			indices = state.onbuildIndices[pending.stage]
			cursor := cursors[pending.stage]
			for cursor < len(indices) && indices[cursor] < pending.index {
				prefix.invalidateOnbuildConfig(indices[cursor])
				cursor++
			}
			cursors[pending.stage] = cursor
		}
		advanceCurrent := func() {
			if prefix == nil {
				return
			}
			cursor := cursors[pending.stage]
			if cursor < len(indices) && indices[cursor] == pending.index {
				prefix.invalidateOnbuildConfig(pending.index)
				cursors[pending.stage] = cursor + 1
			}
		}
		parsed, err := parser.Parse(strings.NewReader(pending.expression))
		if err != nil {
			entry.ParseOK = false
			entry.Error = err.Error()
			advanceCurrent()
			continue
		}
		if len(parsed.AST.Children) != 1 {
			advanceCurrent()
			continue
		}
		inherited := Context{Environment: -1, Arguments: -1, UserInstruction: -1, Deferred: true}
		var inheritedShell []string
		if prefix != nil {
			inherited = cloneContext(&prefix.context)
			inheritedShell = append([]string(nil), prefix.currentShell...)
		}
		child := &analysisState{
			result: &Analysis{
				Instructions: []Instruction{}, Stages: []Stage{},
				Bindings: state.result.Bindings, Contexts: state.result.Contexts,
			},
			current: -1, context: inherited, currentShell: inheritedShell, escape: state.escape,
		}
		child.contextIndex = 0
		child.snapshot()
		child.instruction(parsed.AST.Children[0])
		state.result.Bindings = child.result.Bindings
		state.result.Contexts = child.result.Contexts
		trigger := child.result.Instructions[0]
		trigger.Source = entry.Source
		entry.Trigger = &trigger
		advanceCurrent()
	}
}

func (state *analysisState) execution(command instructions.ShellDependantCmdLine) *Execution {
	result, shellArgv, bodyOnly := state.executionSyntax(command)
	if !command.PrependShell {
		result.Facts = shell.AnalyzeArgv(command.CmdLine)
		return result
	}
	result.Facts = shell.AnalyzeShell(result.Script, shellArgv)
	if bodyOnly || len(command.Files) == 0 {
		locateFacts(result.Facts, state.source.script(state.node, result.Script, bodyOnly))
	}
	return result
}

// runtimeCommandSyntax keeps runtime CMD/ENTRYPOINT structure without parsing
// shell code whose environment and interpreter execute only when the image
// runs. Exec-form argv remains literal and can still be analyzed directly.
func (state *analysisState) runtimeCommandSyntax(command instructions.ShellDependantCmdLine) *Execution {
	result, _, _ := state.executionSyntax(command)
	if !command.PrependShell {
		result.Facts = shell.AnalyzeArgv(command.CmdLine)
		return result
	}
	result.Facts = &shell.Facts{
		Calls:           []shell.Invocation{},
		PackageCommands: []shell.PackageCommand{},
		Scopes:          []shell.Scope{{ID: 0, Parent: -1, Kind: "script"}},
		Complete:        false,
	}
	return result
}

// executionSyntax records the Dockerfile command form and its syntax. It does
// not derive shell facts; callers decide whether the command is safe to parse.
func (state *analysisState) executionSyntax(command instructions.ShellDependantCmdLine) (
	result *Execution,
	shellArgv []string,
	bodyOnly bool,
) {
	result = &Execution{Form: "exec", Argv: command.CmdLine, ShellKnown: len(state.currentShell) > 0}
	if !command.PrependShell {
		return result, nil, false
	}
	result.Form = "shell"
	result.Argv = nil
	result.Shell = state.currentShell
	result.Script = strings.Join(command.CmdLine, " ")
	bodyOnly, explicitInterpreter, hasExplicitInterpreter := false, []string(nil), false
	if len(command.Files) == 1 {
		bodyOnly, explicitInterpreter, hasExplicitInterpreter = heredocInvocation(result.Script, command.Files[0].Name)
	}
	if bodyOnly {
		result.Script = command.Files[0].Data
		if command.Files[0].Chomp {
			result.Script = parser.ChompHeredocContent(result.Script)
		}
	} else {
		for _, file := range command.Files {
			result.Script += "\n" + file.Data + file.Name + "\n"
		}
	}
	shellArgv = []string{defaultShell}
	if len(state.currentShell) > 0 {
		shellArgv = append([]string{state.currentShell[0]}, state.currentShellTail()...)
	}
	if bodyOnly {
		if hasExplicitInterpreter {
			shellArgv = explicitInterpreter
			result.Shell = append([]string(nil), explicitInterpreter...)
			result.ShellKnown = true
		} else if interpreter, ok := heredocInterpreter(result.Script); ok {
			shellArgv = interpreter
			result.Shell = append([]string(nil), interpreter...)
			result.ShellKnown = true
		}
	}
	return result, shellArgv, bodyOnly
}

// heredocInvocation recognizes a heredoc used as an interpreter's stdin, as in
// RUN <<EOF bash. Other shell commands that merely consume heredoc input stay
// on the regular shell parsing path.
func heredocInvocation(command, name string) (bodyOnly bool, interpreter []string, explicit bool) {
	fields := strings.Fields(command)
	marker := -1
	for i, field := range fields {
		heredoc, _ := parser.ParseHeredoc(field)
		if heredoc != nil && heredoc.Name == name {
			marker = i
			break
		}
	}
	if marker < 0 || marker != 0 {
		return false, nil, false
	}
	remaining := fields[marker+1:]
	if len(remaining) == 0 {
		return true, nil, false
	}
	if remaining[0] == "|" && len(remaining) == 2 {
		remaining = remaining[1:]
	}
	for _, argument := range remaining {
		if strings.ContainsAny(argument, "|&;<>()$`\\\"'") {
			return true, []string{unknownInterpreter}, true
		}
	}
	return true, normalizeInterpreter(remaining), true
}

func normalizeInterpreter(argv []string) []string {
	if len(argv) == 0 {
		return []string{unknownInterpreter}
	}
	if path.Base(argv[0]) == envCommand {
		argv = argv[1:]
		if len(argv) > 0 && argv[0] == "-S" {
			argv = argv[1:]
		}
	}
	if len(argv) == 0 {
		return []string{unknownInterpreter}
	}
	return argv
}

// heredocInterpreter reads an explicit script shebang. For /usr/bin/env, the
// command following env is the interpreter; unsupported interpreters are
// still passed to AnalyzeShell so it returns incomplete facts without parsing
// their syntax as a shell.
func heredocInterpreter(script string) ([]string, bool) {
	first, _, _ := strings.Cut(script, "\n")
	first = strings.TrimSpace(first)
	if !strings.HasPrefix(first, "#!") {
		return nil, false
	}
	fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(first, "#!")))
	if len(fields) == 0 {
		return []string{""}, true
	}
	return normalizeInterpreter(fields), true
}

func (state *analysisState) copyStage(fact *Copy) {
	if state.current < 0 || fact.From == nil || !fact.From.Known || fact.From.Text == "" {
		return
	}
	if index, err := strconv.Atoi(fact.From.Text); err == nil && index >= 0 && index < state.current {
		fact.SourceStage = index
		return
	}
	resolved := state.image(fact.From.Text, state.result.Stages[:state.current])
	fact.SourceStage = resolved.Stage
}

func (state *analysisState) healthcheck(entry *Instruction, command *instructions.HealthCheckCommand) {
	health := command.Health
	if health == nil {
		return
	}
	entry.Healthcheck = &Healthcheck{
		Known: true, Configured: true,
		Disabled: len(health.Test) > 0 && health.Test[0] == "NONE",
		Interval: durationText(health.Interval), Timeout: durationText(health.Timeout),
		StartPeriod: durationText(health.StartPeriod), StartInterval: durationText(health.StartInterval), Retries: health.Retries,
	}
	if len(health.Test) > 1 {
		line := instructions.ShellDependantCmdLine{CmdLine: health.Test[1:], PrependShell: health.Test[0] == "CMD-SHELL"}
		entry.Execution = state.execution(line)
		entry.Healthcheck.Syntax = commandSyntaxFromExecution(entry.Execution)
		entry.Healthcheck.Execution = entry.Execution
	}
	state.context.Healthcheck = cloneHealthcheck(entry.Healthcheck)
	state.context.HealthcheckSet = true
	state.context.HealthcheckSetUnknown = false
}

func durationText(duration time.Duration) string {
	if duration == 0 {
		return ""
	}
	return duration.String()
}

func (state *analysisState) snapshot() {
	state.context.EnvironmentValues = state.environmentValues()
	state.context.Shell = append([]string(nil), state.currentShell...)
	state.context.ShellKnown = len(state.currentShell) > 0
	if sameContext(&state.context, &state.result.Contexts[state.contextIndex]) {
		return
	}
	state.contextIndex = len(state.result.Contexts)
	state.result.Contexts = append(state.result.Contexts, state.context)
}

func sameContext(a, b *Context) bool {
	return sameContextState(a, b) && sameContextValues(a, b)
}

func sameContextState(a, b *Context) bool {
	return a.Deferred == b.Deferred && a.Environment == b.Environment && a.Arguments == b.Arguments &&
		a.UserSet == b.UserSet && a.UserSetUnknown == b.UserSetUnknown &&
		a.UserInstruction == b.UserInstruction && a.UserInstructionUnknown == b.UserInstructionUnknown &&
		a.ShellKnown == b.ShellKnown && a.HealthcheckSet == b.HealthcheckSet &&
		a.HealthcheckSetUnknown == b.HealthcheckSetUnknown && slices.Equal(a.Shell, b.Shell)
}

func sameContextValues(a, b *Context) bool {
	return sameValue(&a.User, &b.User) && sameOptionalValue(a.UserName, b.UserName) && sameValue(&a.Workdir, &b.Workdir) &&
		reflect.DeepEqual(a.Healthcheck, b.Healthcheck) && reflect.DeepEqual(a.EnvironmentValues, b.EnvironmentValues)
}
func sameValue(a, b *shell.Value) bool {
	return a.Raw == b.Raw && a.Text == b.Text && a.Known == b.Known && a.Pattern == b.Pattern &&
		slices.Equal(a.References, b.References) && sameDefault(a.Default, b.Default)
}

func sameOptionalValue(a, b *shell.Value) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return sameValue(a, b)
}

func (state *analysisState) currentShellTail() []string {
	if len(state.currentShell) > 1 {
		return state.currentShell[1:]
	}
	return nil
}

func sameDefault(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func (state *analysisState) environmentValues() map[string]shell.Value {
	values := make(map[string]shell.Value)
	var chain []BindingScope
	for frame, remaining := state.context.Environment, len(state.result.Bindings); frame >= 0 && remaining > 0; remaining-- {
		if frame >= len(state.result.Bindings) {
			break
		}
		scope := state.result.Bindings[frame]
		chain = append(chain, scope)
		frame = scope.Parent
	}
	for i := len(chain) - 1; i >= 0; i-- {
		for _, binding := range chain[i].Bindings {
			values[binding.Name] = binding.Value
		}
	}
	return values
}

func cloneContext(source *Context) Context {
	cloned := *source
	if source.UserName != nil {
		userName := *source.UserName
		cloned.UserName = &userName
	}
	cloned.Shell = append([]string(nil), source.Shell...)
	if source.EnvironmentValues != nil {
		values := make(map[string]shell.Value, len(source.EnvironmentValues))
		for key, value := range source.EnvironmentValues {
			values[key] = value
		}
		cloned.EnvironmentValues = values
	}
	cloned.Healthcheck = cloneHealthcheck(source.Healthcheck)
	return cloned
}

func cloneHealthcheck(healthcheck *Healthcheck) *Healthcheck {
	if healthcheck == nil {
		return nil
	}
	cloned := *healthcheck
	return &cloned
}
