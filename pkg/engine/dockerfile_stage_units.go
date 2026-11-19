package engine

import (
	"fmt"

	"github.com/open-policy-agent/opa/v1/ast"
)

func dockerStageRoots(roots []dockerBuildRoot) ([]dockerBuildRoot, error) {
	var selected []dockerBuildRoot
	for _, root := range roots {
		modelTerm := root.doc.Get(ast.StringTerm("_dockerfile"))
		if modelTerm == nil {
			return nil, fmt.Errorf("dockerfile root %q is missing its model", root.id)
		}
		originalModel, ok := modelTerm.Value.(ast.Object)
		if !ok {
			return nil, fmt.Errorf("dockerfile root %q has an invalid model", root.id)
		}
		stages, err := dockerModelArray(root.id, originalModel, "stages")
		if err != nil {
			return nil, err
		}
		for i := 0; i < stages.Len(); i++ {
			stage := stages.Elem(i)
			unitRoot, err := newDockerStageRoot(root, originalModel, stage, i)
			if err != nil {
				return nil, err
			}
			selected = append(selected, unitRoot)
		}
	}
	return selected, nil
}

func newDockerStageRoot(parent dockerBuildRoot, originalModel ast.Object, stageTerm *ast.Term, stageIndex int) (dockerBuildRoot, error) {
	stage, ok := stageTerm.Value.(ast.Object)
	if !ok {
		return dockerBuildRoot{}, fmt.Errorf("dockerfile root %q stage %d is invalid", parent.id, stageIndex)
	}
	if err := validateDockerNodeIdentity(parent.id, stage, "stages", stageIndex); err != nil {
		return dockerBuildRoot{}, err
	}
	if err := validateDockerIndex(parent.id, stage, stageIndex); err != nil {
		return dockerBuildRoot{}, err
	}

	stages, err := dockerModelArray(parent.id, originalModel, "stages")
	if err != nil {
		return dockerBuildRoot{}, err
	}
	instructions, err := dockerModelArray(parent.id, originalModel, "instructions")
	if err != nil {
		return dockerBuildRoot{}, err
	}
	contexts, err := dockerModelArray(parent.id, originalModel, "contexts")
	if err != nil {
		return dockerBuildRoot{}, err
	}
	fromTerm, err := dockerRelatedInstruction(parent.id, stage, instructions, "from", "from", stageIndex, stages.Len())
	if err != nil {
		return dockerBuildRoot{}, err
	}
	contextIndex, err := dockerKnownIndex(parent.id, stage, "context", contexts.Len(), stageIndex)
	if err != nil {
		return dockerBuildRoot{}, err
	}
	contextTerm := contexts.Elem(contextIndex)
	if _, ok := contextTerm.Value.(ast.Object); !ok {
		return dockerBuildRoot{}, fmt.Errorf("dockerfile root %q stage %d context %d is invalid", parent.id, stageIndex, contextIndex)
	}

	originFrom, err := dockerOriginFrom(parent, originalModel, stage, instructions, stageIndex)
	if err != nil {
		return dockerBuildRoot{}, err
	}
	userInstruction, err := dockerUserInstruction(parent, contextTerm.Value.(ast.Object), instructions, stageIndex)
	if err != nil {
		return dockerBuildRoot{}, err
	}

	unitModel := ast.NewObject()
	for _, field := range []string{"contract_version", "resource_type", "resource_name"} {
		if value := originalModel.Get(ast.StringTerm(field)); value != nil {
			unitModel.Insert(ast.StringTerm(field), value)
		}
	}
	unitModel.Insert(ast.StringTerm("stage"), stageTerm)
	unitModel.Insert(ast.StringTerm("context"), contextTerm)
	unitModel.Insert(ast.StringTerm("from"), fromTerm)
	unitModel.Insert(ast.StringTerm("origin_from"), originFrom)
	unitModel.Insert(ast.StringTerm("user_instruction"), userInstruction)

	unitDocument := ast.NewObject()
	unitDocument.Insert(ast.StringTerm("id"), ast.StringTerm(parent.id))
	unitDocument.Insert(ast.StringTerm("_dockerfile"), ast.NewTerm(unitModel))
	term := ast.NewTerm(unitDocument)
	return dockerBuildRoot{id: parent.id, doc: unitDocument, term: term, stageUnit: true, unknownValue: parent.unknownValue}, nil
}

func dockerModelArray(rootID string, facts ast.Object, field string) (*ast.Array, error) {
	term := facts.Get(ast.StringTerm(field))
	if term == nil {
		return nil, fmt.Errorf("dockerfile root %q is missing model field %q", rootID, field)
	}
	array, ok := term.Value.(*ast.Array)
	if !ok {
		return nil, fmt.Errorf("dockerfile root %q model field %q must be an array", rootID, field)
	}
	return array, nil
}

func validateDockerIndex(rootID string, node ast.Object, expected int) error {
	term := node.Get(ast.StringTerm("index"))
	if term == nil {
		return fmt.Errorf("dockerfile root %q node is missing index", rootID)
	}
	value, ok := term.Value.(ast.Number)
	if !ok {
		return fmt.Errorf("dockerfile root %q node field index must be an integer", rootID)
	}
	index, integer := value.Int()
	if !integer || index != expected {
		return fmt.Errorf("dockerfile root %q node field index does not match source index %d", rootID, expected)
	}
	return nil
}

func validateDockerNodeIdentity(rootID string, node ast.Object, collection string, index int) error {
	metadataTerm := node.Get(ast.StringTerm("_dd_meta"))
	metadata, ok := objectValue(metadataTerm)
	if !ok {
		return fmt.Errorf("dockerfile root %q %s node %d is missing identity metadata", rootID, collection, index)
	}
	idTerm := metadata.Get(ast.StringTerm("id"))
	id, ok := idTermString(idTerm)
	expected := fmt.Sprintf("%s#/_dockerfile/%s/%d", rootID, collection, index)
	if !ok || id != expected {
		return fmt.Errorf("dockerfile root %q %s node %d has invalid identity", rootID, collection, index)
	}
	return nil
}

func objectValue(term *ast.Term) (ast.Object, bool) {
	if term == nil {
		return nil, false
	}
	value, ok := term.Value.(ast.Object)
	return value, ok
}

func idTermString(term *ast.Term) (string, bool) {
	if term == nil {
		return "", false
	}
	value, ok := term.Value.(ast.String)
	return string(value), ok
}

func dockerKnownIndex(rootID string, node ast.Object, field string, limit, stageIndex int) (int, error) {
	term := node.Get(ast.StringTerm(field))
	if term == nil {
		return 0, fmt.Errorf("dockerfile root %q stage %d is missing relation %q", rootID, stageIndex, field)
	}
	value, ok := term.Value.(ast.Number)
	if !ok {
		return 0, fmt.Errorf("dockerfile root %q stage %d relation %q is not a known index", rootID, stageIndex, field)
	}
	index, integer := value.Int()
	if !integer || index < 0 || index >= limit {
		return 0, fmt.Errorf("dockerfile root %q stage %d relation %q has invalid index", rootID, stageIndex, field)
	}
	return index, nil
}

func dockerRelatedInstruction(
	rootID string, source ast.Object, instructions *ast.Array, relation, expectedKind string, stageIndex, stageCount int,
) (*ast.Term, error) {
	index, err := dockerKnownIndex(rootID, source, relation, instructions.Len(), stageIndex)
	if err != nil {
		return nil, err
	}
	term := instructions.Elem(index)
	instruction, ok := term.Value.(ast.Object)
	if !ok {
		return nil, fmt.Errorf("dockerfile root %q stage %d related instruction %d is invalid", rootID, stageIndex, index)
	}
	if err := validateDockerIndex(rootID, instruction, index); err != nil {
		return nil, err
	}
	if err := validateDockerNodeIdentity(rootID, instruction, "instructions", index); err != nil {
		return nil, err
	}
	actualKind, ok := kindTermString(instruction.Get(ast.StringTerm("kind")))
	if !ok || actualKind != expectedKind {
		return nil, fmt.Errorf(
			"dockerfile root %q stage %d relation %q does not reference a %s instruction",
			rootID, stageIndex, relation, expectedKind,
		)
	}
	if err := validateDockerFromInstruction(rootID, instruction, stageIndex, stageCount); err != nil {
		return nil, err
	}
	return term, nil
}

func validateDockerFromInstruction(rootID string, instruction ast.Object, stageIndex, stageCount int) error {
	stageTerm := instruction.Get(ast.StringTerm("stage"))
	stage, ok := integerTerm(stageTerm)
	if !ok || stage != stageIndex {
		return fmt.Errorf("dockerfile root %q FROM instruction does not belong to related stage %d", rootID, stageIndex)
	}
	finalTerm := instruction.Get(ast.StringTerm("final_stage"))
	final, ok := boolTerm(finalTerm)
	if !ok || final != (stageIndex == stageCount-1) {
		return fmt.Errorf("dockerfile root %q FROM instruction has invalid final_stage for stage %d", rootID, stageIndex)
	}
	return nil
}

func integerTerm(term *ast.Term) (int, bool) {
	if term == nil {
		return 0, false
	}
	number, ok := term.Value.(ast.Number)
	if !ok {
		return 0, false
	}
	return number.Int()
}

func boolTerm(term *ast.Term) (value, ok bool) {
	if term == nil {
		return false, false
	}
	booleanValue, ok := term.Value.(ast.Boolean)
	return bool(booleanValue), ok
}

func dockerOriginFrom(parent dockerBuildRoot, originalModel, stage ast.Object, instructions *ast.Array, stageIndex int) (*ast.Term, error) {
	originTerm := stage.Get(ast.StringTerm("origin_stage"))
	if originTerm == nil {
		return nil, fmt.Errorf("dockerfile root %q stage %d is missing origin_stage", parent.id, stageIndex)
	}
	originNumber, ok := originTerm.Value.(ast.Number)
	if !ok {
		unknown, isString := originTerm.Value.(ast.String)
		if isString && parent.unknownValue != "" && string(unknown) == parent.unknownValue {
			return originTerm, nil
		}
		return nil, fmt.Errorf("dockerfile root %q stage %d has invalid origin_stage", parent.id, stageIndex)
	}
	origin, integer := originNumber.Int()
	if !integer {
		return nil, fmt.Errorf("dockerfile root %q stage %d has invalid origin_stage", parent.id, stageIndex)
	}
	stages, err := dockerModelArray(parent.id, originalModel, "stages")
	if err != nil {
		return nil, err
	}
	if origin < 0 || origin >= stages.Len() {
		return nil, fmt.Errorf("dockerfile root %q stage %d origin_stage index is out of range", parent.id, stageIndex)
	}
	originStage, ok := stages.Elem(origin).Value.(ast.Object)
	if !ok {
		return nil, fmt.Errorf("dockerfile root %q stage %d origin_stage %d is invalid", parent.id, stageIndex, origin)
	}
	if err := validateDockerIndex(parent.id, originStage, origin); err != nil {
		return nil, err
	}
	if err := validateDockerNodeIdentity(parent.id, originStage, "stages", origin); err != nil {
		return nil, err
	}
	term, err := dockerRelatedInstruction(parent.id, originStage, instructions, "from", "from", origin, stages.Len())
	return term, err
}

func dockerUserInstruction(parent dockerBuildRoot, context ast.Object, instructions *ast.Array, stageIndex int) (*ast.Term, error) {
	userTerm := context.Get(ast.StringTerm("user_instruction"))
	if userTerm == nil {
		return nil, fmt.Errorf("dockerfile root %q stage %d context is missing user_instruction", parent.id, stageIndex)
	}
	value, ok := userTerm.Value.(ast.Number)
	if !ok {
		unknown, isString := userTerm.Value.(ast.String)
		if isString && parent.unknownValue != "" && string(unknown) == parent.unknownValue {
			return userTerm, nil
		}
		return nil, fmt.Errorf("dockerfile root %q stage %d context has invalid user_instruction", parent.id, stageIndex)
	}
	index, integer := value.Int()
	if !integer || index < -1 {
		return nil, fmt.Errorf("dockerfile root %q stage %d context has invalid user_instruction", parent.id, stageIndex)
	}
	if index == -1 {
		return ast.NewTerm(ast.Null{}), nil
	}
	if index >= instructions.Len() {
		return nil, fmt.Errorf("dockerfile root %q stage %d user_instruction index is out of range", parent.id, stageIndex)
	}
	term := instructions.Elem(index)
	instruction, ok := term.Value.(ast.Object)
	if !ok {
		return nil, fmt.Errorf("dockerfile root %q stage %d user_instruction %d is invalid", parent.id, stageIndex, index)
	}
	kind, ok := kindTermString(instruction.Get(ast.StringTerm("kind")))
	if !ok || kind != "user" {
		return nil, fmt.Errorf("dockerfile root %q stage %d user_instruction %d is not a USER instruction", parent.id, stageIndex, index)
	}
	if err := validateDockerIndex(parent.id, instruction, index); err != nil {
		return nil, err
	}
	if err := validateDockerNodeIdentity(parent.id, instruction, "instructions", index); err != nil {
		return nil, err
	}
	return term, nil
}
