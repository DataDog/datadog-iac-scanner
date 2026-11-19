package docker

import (
	"strconv"
	"strings"
)

// finalizeCopyStageRelations resolves COPY --from references after every
// top-level stage has been parsed. Unlike FROM bases, COPY sources may point
// to a later stage.
func finalizeCopyStageRelations(analysis *Analysis) {
	if analysis == nil || len(analysis.Stages) == 0 {
		return
	}

	stagesByName := make(map[string]int, len(analysis.Stages))
	for index := range analysis.Stages {
		stage := &analysis.Stages[index]
		if stage.Name == "" {
			continue
		}
		// BuildKit resolves stage aliases case-insensitively, with the last
		// registered alias winning if an invalid Dockerfile repeats a name.
		stagesByName[strings.ToLower(stage.Name)] = index
	}

	for index := range analysis.Instructions {
		copyFact := analysis.Instructions[index].Copy
		if copyFact == nil || copyFact.From == nil || !copyFact.From.Known || copyFact.From.Text == "" {
			continue
		}

		copyFact.SourceStage = -1
		if stageIndex, err := strconv.Atoi(copyFact.From.Text); err == nil {
			if stageIndex >= 0 && stageIndex < len(analysis.Stages) {
				copyFact.SourceStage = stageIndex
			}
			continue
		}

		if stageIndex, ok := stagesByName[strings.ToLower(copyFact.From.Text)]; ok {
			copyFact.SourceStage = stageIndex
		}
	}
}
