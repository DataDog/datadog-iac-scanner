package docker

type instructionKindStage struct {
	stage int
	kind  string
}

// assignFirstOfKindInStage marks the first top-level source instruction for
// each kind within each stage. Nested ONBUILD triggers are not in the
// top-level instruction slice and do not participate in this inventory.
func assignFirstOfKindInStage(analysis *Analysis) {
	seen := make(map[instructionKindStage]bool, len(analysis.Instructions))
	for index := range analysis.Instructions {
		instruction := &analysis.Instructions[index]
		key := instructionKindStage{stage: instruction.Stage, kind: instruction.Kind}
		instruction.FirstOfKindInStage = !seen[key]
		seen[key] = true
	}
}
