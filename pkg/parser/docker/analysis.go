package docker

import (
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/shell"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

const environmentBindings = "environment"

type Analysis struct {
	// ResourceType and ResourceName identify the findings of rules using this
	// model, as the legacy rules name every Dockerfile.
	ResourceType    string         `json:"resource_type"`
	ResourceName    string         `json:"resource_name"`
	Instructions    []Instruction  `json:"instructions"`
	Stages          []Stage        `json:"stages"`
	Bindings        []BindingScope `json:"bindings"`
	GlobalArguments int            `json:"global_arguments"`
	Contexts        []Context      `json:"contexts"`
}

type Stage struct {
	Index     int          `json:"index"`
	Name      string       `json:"name"`
	BaseStage int          `json:"base_stage"`
	From      int          `json:"from"`
	Context   int          `json:"context"`
	Source    model.Source `json:"source"`
}

type Instruction struct {
	Kind        string        `json:"kind"`
	Flags       []Flag        `json:"flags,omitempty"`
	Healthcheck *Healthcheck  `json:"healthcheck,omitempty"`
	Stage       int           `json:"stage"`
	Source      model.Source  `json:"source"`
	Image       *Image        `json:"image,omitempty"`
	Platform    *shell.Value  `json:"platform,omitempty"`
	Copy        *Copy         `json:"copy,omitempty"`
	Bindings    []Binding     `json:"bindings,omitempty"`
	Value       *shell.Value  `json:"value,omitempty"`
	Values      []shell.Value `json:"values,omitempty"`
	Mounts      []Mount       `json:"mounts,omitempty"`
	Execution   *Execution    `json:"execution,omitempty"`
	TriggerKind string        `json:"trigger_kind,omitempty"`
	Trigger     *Instruction  `json:"trigger,omitempty"`
	Context     int           `json:"context"`
	ParseOK     bool          `json:"parse_ok"`
	Error       string        `json:"error,omitempty"`
}

// Execution is what an instruction runs, with the facts of its command line.
type Execution struct {
	Form       string   `json:"form"`
	Argv       []string `json:"argv,omitempty"`
	Script     string   `json:"script,omitempty"`
	Shell      []string `json:"shell,omitempty"`
	ShellKnown bool     `json:"shell_known"`
	*shell.Facts
}

type analysisState struct {
	result        *Analysis
	current       int
	currentShell  []string
	stageContexts []Context
	stageShells   [][]string
	context       Context
	contextIndex  int
	pending       []pendingTrigger
	// source locates the instruction being analyzed; it is nil for ONBUILD
	// triggers, whose text is not where they run.
	source *source
	node   *parser.Node
}

type pendingTrigger struct {
	index, stage int
	expression   string
}

func analyze(ast *parser.Node, src *source) *Analysis {
	state := &analysisState{
		result: &Analysis{
			ResourceType: dockerResource, ResourceName: dockerResource,
			Instructions: []Instruction{}, Stages: []Stage{},
			Bindings: []BindingScope{{Parent: -1, Kind: "build_arguments", Bindings: []Binding{}}},
			Contexts: []Context{{Environment: -1, Arguments: 0}},
		},
		current: -1, context: Context{Environment: -1, Arguments: 0}, source: src,
	}
	for _, node := range ast.Children {
		state.instruction(node)
	}
	state.finishTriggers()
	return state.result
}

func (state *analysisState) instruction(node *parser.Node) {
	typed, err := instructions.ParseInstruction(node)
	state.node = node
	kind := strings.ToLower(node.Value)
	entry := Instruction{Kind: kind, ParseOK: err == nil, Source: state.source.instruction(node)}
	if kind == dockerFrom {
		state.beginStage(typed, entry.Source)
	}
	entry.Stage, entry.Context = state.current, state.contextIndex
	if kind == "onbuild" && node.Next != nil && len(node.Next.Children) > 0 {
		entry.TriggerKind = strings.ToLower(node.Next.Children[0].Value)
	}
	for _, raw := range node.Flags {
		name, text, hasValue := strings.Cut(strings.TrimPrefix(raw, "--"), "=")
		if !hasValue {
			text = "true"
		}
		entry.Flags = append(entry.Flags, Flag{Name: name, Value: value(text)})
	}
	if err != nil {
		entry.Error = err.Error()
	} else {
		state.enrich(&entry, typed)
	}
	state.snapshot()
	state.result.Instructions = append(state.result.Instructions, entry)
	if state.current >= 0 {
		state.stageContexts[state.current] = state.context
		state.result.Stages[state.current].Context = state.contextIndex
	}
}

func (state *analysisState) beginStage(typed any, source model.Source) {
	state.current = len(state.result.Stages)
	state.currentShell = nil
	state.context = Context{Environment: -1, Arguments: -1}
	stage := Stage{Index: state.current, From: len(state.result.Instructions), BaseStage: -1, Source: source}
	if command, ok := typed.(*instructions.Stage); ok {
		stage.Name = command.Name
		base := image(command.BaseName, state.result.Stages)
		stage.BaseStage = base.Stage
		if base.Stage >= 0 {
			state.currentShell = state.stageShells[base.Stage]
			state.context = state.stageContexts[base.Stage]
		}
	}
	state.result.Stages = append(state.result.Stages, stage)
	state.stageShells = append(state.stageShells, state.currentShell)
	state.stageContexts = append(state.stageContexts, state.context)
	state.snapshot()
}

func (state *analysisState) enrich(entry *Instruction, typed any) {
	switch command := typed.(type) {
	case *instructions.Stage:
		entry.Image = state.imageFact(command.BaseName)
		entry.Platform = optionalValue(command.Platform)
	case *instructions.AddCommand, *instructions.CopyCommand:
		entry.Copy = copyFacts(command)
		state.copyStage(entry.Copy)
	case *instructions.RunCommand:
		state.run(entry, command)
	case *instructions.CmdCommand:
		entry.Execution = state.execution(command.ShellDependantCmdLine)
	case *instructions.EntrypointCommand:
		entry.Execution = state.execution(command.ShellDependantCmdLine)
	case *instructions.ShellCommand:
		state.currentShell = command.Shell
		if state.current >= 0 {
			state.stageShells[state.current] = command.Shell
		}
		entry.Values = values(command.Shell)
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
		entry.Values = values(command.Ports)
	case *instructions.VolumeCommand:
		entry.Values = values(command.Volumes)
	case *instructions.StopSignalCommand:
		v := value(command.Signal)
		entry.Value = &v
	case *instructions.MaintainerCommand:
		v := value(command.Maintainer)
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
		state.bind(entry, "arguments")
	case *instructions.LabelCommand:
		for _, binding := range command.Labels {
			entry.Bindings = append(entry.Bindings, Binding{Name: binding.Key, Value: state.declaredValue(binding.Value), HasDefault: true})
		}
	}
}

func values(raw []string) []shell.Value {
	result := make([]shell.Value, len(raw))
	for i, text := range raw {
		result[i] = value(text)
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
				Kind: string(mount.Type), Target: value(mount.Target), Source: value(mount.Source), From: optionalValue(mount.From),
				ReadOnly: mount.ReadOnly, CacheID: value(mount.CacheID), Sharing: string(mount.CacheSharing), Required: mount.Required,
			})
		}
	}
	entry.Execution = state.execution(command.ShellDependantCmdLine)
}

// ONBUILD is evaluated downstream against the declaring image's final
// configuration. Its stage graph and build arguments belong to the child.
func (state *analysisState) finishTriggers() {
	for _, pending := range state.pending {
		entry := &state.result.Instructions[pending.index]
		parsed, err := parser.Parse(strings.NewReader(pending.expression))
		if err != nil {
			entry.ParseOK = false
			entry.Error = err.Error()
			continue
		}
		if len(parsed.AST.Children) != 1 {
			continue
		}
		inherited := Context{Environment: -1, Arguments: -1, Deferred: true}
		var inheritedShell []string
		if pending.stage >= 0 {
			inherited = state.stageContexts[pending.stage]
			inherited.Arguments = -1
			inherited.Deferred = true
			inheritedShell = state.stageShells[pending.stage]
		}
		child := &analysisState{
			result: &Analysis{
				Instructions: []Instruction{}, Stages: []Stage{},
				Bindings: state.result.Bindings, Contexts: state.result.Contexts,
			},
			current: -1, context: inherited, currentShell: inheritedShell,
		}
		child.contextIndex = 0
		child.snapshot()
		child.instruction(parsed.AST.Children[0])
		state.result.Bindings = child.result.Bindings
		state.result.Contexts = child.result.Contexts
		trigger := child.result.Instructions[0]
		trigger.Source = entry.Source
		entry.Trigger = &trigger
	}
}

func (state *analysisState) execution(command instructions.ShellDependantCmdLine) *Execution {
	result := &Execution{Form: "exec", Argv: command.CmdLine, ShellKnown: len(state.currentShell) > 0}
	if !command.PrependShell {
		result.Facts = shell.AnalyzeArgv(command.CmdLine)
		return result
	}
	result.Form = "shell"
	result.Argv = nil
	result.Shell = state.currentShell
	result.Script = strings.Join(command.CmdLine, " ")
	heredoc, _ := parser.ParseHeredoc(strings.TrimSpace(result.Script))
	bodyOnly := len(command.Files) == 1 && heredoc != nil && heredoc.Name == command.Files[0].Name
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
	shellName := "sh"
	if len(state.currentShell) > 0 {
		shellName = state.currentShell[0]
	}
	result.Facts = shell.AnalyzeShell(result.Script, append([]string{shellName}, state.currentShellTail()...))
	if bodyOnly || len(command.Files) == 0 {
		locateFacts(result.Facts, state.source.script(state.node, result.Script, bodyOnly))
	}
	return result
}

func (state *analysisState) copyStage(fact *Copy) {
	if state.current < 0 || fact.From == nil || !fact.From.Known || fact.From.Text == "" {
		return
	}
	if index, err := strconv.Atoi(fact.From.Text); err == nil && index >= 0 && index < state.current {
		fact.SourceStage = index
		return
	}
	resolved := image(fact.From.Text, state.result.Stages[:state.current])
	fact.SourceStage = resolved.Stage
}

func (state *analysisState) healthcheck(entry *Instruction, command *instructions.HealthCheckCommand) {
	health := command.Health
	if health == nil {
		return
	}
	entry.Healthcheck = &Healthcheck{
		Disabled: len(health.Test) > 0 && health.Test[0] == "NONE",
		Interval: durationText(health.Interval), Timeout: durationText(health.Timeout),
		StartPeriod: durationText(health.StartPeriod), StartInterval: durationText(health.StartInterval), Retries: health.Retries,
	}
	if len(health.Test) > 1 {
		line := instructions.ShellDependantCmdLine{CmdLine: health.Test[1:], PrependShell: health.Test[0] == "CMD-SHELL"}
		entry.Execution = state.execution(line)
	}
}

func durationText(duration time.Duration) string {
	if duration == 0 {
		return ""
	}
	return duration.String()
}

func (state *analysisState) snapshot() {
	if sameContext(&state.context, &state.result.Contexts[state.contextIndex]) {
		return
	}
	state.contextIndex = len(state.result.Contexts)
	state.result.Contexts = append(state.result.Contexts, state.context)
}

func sameContext(a, b *Context) bool {
	return a.Deferred == b.Deferred && a.Environment == b.Environment && a.Arguments == b.Arguments &&
		sameValue(&a.User, &b.User) && sameValue(&a.Workdir, &b.Workdir)
}
func sameValue(a, b *shell.Value) bool {
	return a.Raw == b.Raw && a.Text == b.Text && a.Known == b.Known && a.Pattern == b.Pattern &&
		slices.Equal(a.References, b.References) && sameDefault(a.Default, b.Default)
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
