package docker

// assignLastOfKindInStage marks the last top-level source instruction for
// each kind within each stage. Nested ONBUILD triggers are excluded because
// only top-level instructions participate in stage source order.
func assignLastOfKindInStage(analysis *Analysis) {
	seen := make(map[instructionKindStage]bool, len(analysis.Instructions))
	for index := len(analysis.Instructions) - 1; index >= 0; index-- {
		instruction := &analysis.Instructions[index]
		key := instructionKindStage{stage: instruction.Stage, kind: instruction.Kind}
		instruction.LastOfKindInStage = !seen[key]
		seen[key] = true
	}
}
