package engine

import (
	"fmt"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/open-policy-agent/opa/v1/ast"
)

const (
	dockerUnitScopeInstruction = "instruction"
	dockerUnitScopeDockerfile  = "dockerfile"
	dockerUnitScopeStage       = "stage"
)

// dockerUnitRoots applies a rule's explicit unit contract
// to otherwise independent Dockerfile roots. Without that annotation, each
// root remains the complete Dockerfile and all its stages and context facts.
func dockerUnitRoots(query *model.QueryMetadata, roots []dockerBuildRoot) ([]dockerBuildRoot, error) {
	spec, configured, err := dockerInstructionUnit(query)
	if err != nil {
		return nil, err
	}
	if !configured {
		return roots, nil
	}
	if spec.scope == dockerUnitScopeDockerfile {
		return roots, nil
	}
	if spec.scope == dockerUnitScopeStage {
		return dockerStageRoots(roots)
	}
	selected := make([]dockerBuildRoot, 0, len(roots))
	for _, root := range roots {
		term := root.doc.Get(ast.StringTerm("_dockerfile"))
		if term == nil {
			return nil, fmt.Errorf("dockerfile root %q is missing its model", root.id)
		}
		dockerModel, ok := term.Value.(ast.Object)
		if !ok {
			return nil, fmt.Errorf("dockerfile root %q has an invalid model", root.id)
		}
		instructionsTerm := dockerModel.Get(ast.StringTerm("instructions"))
		if instructionsTerm == nil {
			return nil, fmt.Errorf("dockerfile root %q is missing instructions", root.id)
		}
		instructions, ok := instructionsTerm.Value.(*ast.Array)
		if !ok {
			return nil, fmt.Errorf("dockerfile root %q has invalid instructions", root.id)
		}
		for i := 0; i < instructions.Len(); i++ {
			instructionTerm := instructions.Elem(i)
			instruction, ok := instructionTerm.Value.(ast.Object)
			if !ok {
				return nil, fmt.Errorf("dockerfile root %q instruction %d is invalid", root.id, i)
			}
			kindTerm := instruction.Get(ast.StringTerm("kind"))
			kind, ok := kindTermString(kindTerm)
			if !ok || (spec.kinds != nil && !spec.kinds[kind]) {
				continue
			}
			unitRoot := newDockerInstructionRoot(root, dockerModel, instructionTerm)
			selected = append(selected, unitRoot)
		}
	}
	return selected, nil
}

type dockerUnitSpec struct {
	scope string
	kinds map[string]bool
}

func dockerInstructionUnit(query *model.QueryMetadata) (spec dockerUnitSpec, configured bool, err error) {
	if query == nil {
		return dockerUnitSpec{}, false, fmt.Errorf("dockerfile query metadata is missing")
	}
	config, configured, err := dockerUnitConfig(query)
	if err != nil || !configured {
		return dockerUnitSpec{}, configured, err
	}
	return parseDockerUnitSpec(config)
}

func dockerUnitConfig(query *model.QueryMetadata) (config map[string]interface{}, configured bool, err error) {
	module, err := ast.ParseModuleWithOpts(query.Query, query.Content, ast.ParserOptions{
		RegoVersion: ast.RegoV1, ProcessAnnotation: true,
	})
	if err != nil {
		return nil, false, fmt.Errorf("parse Dockerfile rule metadata: %w", err)
	}
	var unitConfig map[string]interface{}
	for _, annotation := range module.Annotations {
		custom := annotation.Custom
		if custom == nil {
			continue
		}
		dockerfile, present, err := dockerfileAnnotation(custom)
		if err != nil {
			return nil, false, err
		}
		if !present {
			continue
		}
		if annotation.Scope != "package" {
			return nil, false, fmt.Errorf("dockerfile unit metadata must have package scope")
		}
		if unitConfig != nil {
			return nil, false, fmt.Errorf("dockerfile unit metadata is declared more than once")
		}
		unitConfig = dockerfile
	}
	if unitConfig == nil {
		return nil, false, nil
	}
	return unitConfig, true, nil
}

func parseDockerUnitSpec(config map[string]interface{}) (dockerUnitSpec, bool, error) {
	for key := range config {
		if key != "version" && key != "scope" && key != "kinds" {
			return dockerUnitSpec{}, false, fmt.Errorf("unknown Dockerfile contract metadata field %q", key)
		}
	}
	if len(config) == 1 {
		if _, versionOnly := config["version"]; versionOnly {
			return dockerUnitSpec{scope: dockerUnitScopeDockerfile}, true, nil
		}
	}
	unit, ok := config["scope"].(string)
	if !ok || (unit != dockerUnitScopeInstruction && unit != dockerUnitScopeDockerfile && unit != dockerUnitScopeStage) {
		return dockerUnitSpec{}, false, fmt.Errorf("dockerfile unit scope must be instruction, stage, or dockerfile")
	}
	spec := dockerUnitSpec{scope: unit}
	kinds, err := dockerScopeKinds(config, unit)
	if err != nil {
		return dockerUnitSpec{}, false, err
	}
	spec.kinds = kinds
	return spec, true, nil
}

func dockerScopeKinds(config map[string]interface{}, scope string) (map[string]bool, error) {
	if scope == dockerUnitScopeInstruction {
		raw, hasKinds := config["kinds"]
		if !hasKinds {
			return nil, nil
		}
		return parseDockerInstructionKinds(raw)
	}
	if _, hasKinds := config["kinds"]; hasKinds {
		return nil, fmt.Errorf("%s scope does not accept instruction kinds", scope)
	}
	return nil, nil
}

func dockerfileAnnotation(custom map[string]interface{}) (dockerfile map[string]interface{}, present bool, err error) {
	rawDatadog, present := custom["datadog"]
	if !present {
		return nil, false, nil
	}
	datadog, ok := rawDatadog.(map[string]interface{})
	if !ok {
		return nil, false, fmt.Errorf("dockerfile custom metadata datadog must be an object")
	}
	rawDockerfile, present := datadog["dockerfile"]
	if !present {
		return nil, false, nil
	}
	dockerfileValue, ok := rawDockerfile.(map[string]interface{})
	if !ok {
		return nil, false, fmt.Errorf("dockerfile unit metadata must be an object")
	}
	return dockerfileValue, true, nil
}

var dockerInstructionKinds = map[string]struct{}{
	"add": {}, "arg": {}, "cmd": {}, "copy": {}, "entrypoint": {}, "env": {}, "expose": {},
	"from": {}, "healthcheck": {}, "label": {}, "maintainer": {}, "onbuild": {}, "run": {},
	"shell": {}, "stopsignal": {}, "user": {}, "volume": {}, "workdir": {},
}

func parseDockerInstructionKinds(raw interface{}) (map[string]bool, error) {
	items, ok := raw.([]interface{})
	if !ok || len(items) == 0 {
		return nil, fmt.Errorf("dockerfile unit kinds must be a non-empty list")
	}
	kinds := make(map[string]bool, len(items))
	for _, item := range items {
		kind, ok := item.(string)
		if !ok || strings.TrimSpace(kind) == "" {
			return nil, fmt.Errorf("dockerfile unit kinds must contain instruction names")
		}
		kind = strings.ToLower(strings.TrimSpace(kind))
		if _, ok := dockerInstructionKinds[kind]; !ok {
			return nil, fmt.Errorf("unknown Dockerfile instruction kind %q", kind)
		}
		kinds[kind] = true
	}
	return kinds, nil
}

func newDockerInstructionRoot(parent dockerBuildRoot, originalModel ast.Object,
	instruction *ast.Term) dockerBuildRoot {
	unitModel := ast.NewObject()
	for _, field := range []string{"contract_version", "resource_type", "resource_name", "stage_names"} {
		if value := originalModel.Get(ast.StringTerm(field)); value != nil {
			unitModel.Insert(ast.StringTerm(field), value)
		}
	}
	if current, ok := instruction.Value.(ast.Object); ok {
		if kind, _ := kindTermString(current.Get(ast.StringTerm("kind"))); kind == dockerRunInstructionKind {
			if inventory := dockerStageRunInventory(originalModel, current); inventory != nil {
				unitModel.Insert(ast.StringTerm("stage_run_commands"), inventory)
			}
		}
	}
	unitModel.Insert(ast.StringTerm("instructions"), ast.NewTerm(ast.NewArray(instruction)))
	unitDocument := ast.NewObject()
	unitDocument.Insert(ast.StringTerm("id"), ast.StringTerm(parent.id))
	unitDocument.Insert(ast.StringTerm("_dockerfile"), ast.NewTerm(unitModel))
	term := ast.NewTerm(unitDocument)
	return dockerBuildRoot{id: parent.id, doc: unitDocument, term: term, instructionUnit: true}
}

func kindTermString(term *ast.Term) (string, bool) {
	if term == nil {
		return "", false
	}
	kind, ok := term.Value.(ast.String)
	return strings.ToLower(string(kind)), ok
}

// Stage inventories are serialized once by the parser. Units share the AST
// term for their stage instead of duplicating that inventory in every RUN.
func dockerStageRunInventory(dockerModel, instruction ast.Object) *ast.Term {
	stageTerm := instruction.Get(ast.StringTerm("stage"))
	stagesTerm := dockerModel.Get(ast.StringTerm("stages"))
	if stageTerm == nil || stagesTerm == nil {
		return nil
	}
	stage, ok := stageTerm.Value.(ast.Number)
	if !ok {
		return nil
	}
	index, ok := stage.Int()
	if !ok || index < 0 {
		return nil
	}
	stages, ok := stagesTerm.Value.(*ast.Array)
	if !ok || index >= stages.Len() {
		return nil
	}
	current, ok := stages.Elem(index).Value.(ast.Object)
	if !ok {
		return nil
	}
	return current.Get(ast.StringTerm("run_commands"))
}
