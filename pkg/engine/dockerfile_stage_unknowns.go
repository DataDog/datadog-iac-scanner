package engine

import (
	"encoding/json"
	"strconv"
)

const dockerUnknownImageKind = "unknown"

// taintUnknownDockerStageRelationships marks stage relationships that cannot
// be known until a dynamic FROM reference is resolved. In particular,
// base_stage == -1 is only a known external-base fact when the FROM reference
// itself is known; an ARG-backed reference may instead name a local stage.
func taintUnknownDockerStageRelationships(facts map[string]interface{}, placeholder string) map[int]bool {
	uncertain := make(map[int]bool)
	stages, ok := facts["stages"].([]interface{})
	if !ok {
		return uncertain
	}
	instructions, _ := facts["instructions"].([]interface{})
	originUnknown := make([]bool, len(stages))
	for i, rawStage := range stages {
		stage, _ := rawStage.(map[string]interface{})
		if markDockerStageBaseUnknown(stage, instructions, placeholder) {
			originUnknown[i], uncertain[i] = true, true
		}
	}

	// A later FROM <stage-name> has a known immediate local base, but its
	// original external base remains unknown when that earlier stage's FROM
	// was dynamic.
	taintUnknownDockerDescendantStages(stages, originUnknown, uncertain, placeholder)
	return uncertain
}

func markDockerStageBaseUnknown(stage map[string]interface{}, instructions []interface{}, placeholder string) bool {
	if stage == nil {
		return false
	}
	fromIndex, ok := dockerFactIndex(stage["from"])
	if !ok || fromIndex < 0 || fromIndex >= len(instructions) {
		return false
	}
	instruction, ok := instructions[fromIndex].(map[string]interface{})
	if !ok {
		return false
	}
	image, ok := instruction["image"].(map[string]interface{})
	if !ok || image["kind"] != dockerUnknownImageKind {
		return false
	}
	reference, ok := image["reference"].(map[string]interface{})
	if !ok || reference["known"] != false {
		return false
	}
	stage["base_stage"] = placeholder
	stage["origin_stage"] = placeholder
	return true
}

func taintUnknownDockerDescendantStages(stages []interface{}, originUnknown []bool, uncertain map[int]bool, placeholder string) {
	for i, rawStage := range stages {
		stage, ok := rawStage.(map[string]interface{})
		if !ok || originUnknown[i] {
			continue
		}
		base, ok := dockerFactIndex(stage["base_stage"])
		if !ok || base < 0 || base >= i || base >= len(originUnknown) || !originUnknown[base] {
			continue
		}
		stage["origin_stage"] = placeholder
		originUnknown[i], uncertain[i] = true, true
	}
}

func dockerFactIndex(value interface{}) (int, bool) {
	switch index := value.(type) {
	case json.Number:
		parsed, err := strconv.Atoi(string(index))
		return parsed, err == nil
	case int:
		return index, true
	case int32:
		return int(index), true
	case int64:
		return int(index), true
	case float64:
		return int(index), index == float64(int(index))
	default:
		return 0, false
	}
}
