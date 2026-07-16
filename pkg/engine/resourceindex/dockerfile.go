/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resourceindex

import (
	"fmt"
	"sort"
	"strings"
)

func indexDockerfileDoc(index, doc map[string]interface{}, docID string) {
	rootEntry := makeEntry(publicDocumentAttrs(doc), docID, "dockerfile", "dockerfile", ddPath())
	setEvalScope(rootEntry, "source", docID)
	addEntry(index, "dockerfile", "dockerfile", rootEntry)

	commands, ok := doc["command"].(map[string]interface{})
	if !ok {
		return
	}

	stages := collectDockerStages(commands)
	for stageOrdinal, stageInfo := range stages {
		stageKey := stageInfo.key
		stage := stageInfo.commands
		baseImage, stageAlias := dockerStageIdentity(stageKey)
		stageScope := fmt.Sprintf("%s:stage:%d", docID, stageOrdinal)

		for idx, cmdRaw := range stage {
			cmd, ok := asMap(cmdRaw)
			if !ok {
				continue
			}
			verb, _ := cmd["Cmd"].(string)
			if verb == "" {
				continue
			}
			verb = strings.ToUpper(verb)
			resourceName := "dockerfile"
			entry := makeEntry(cmd, docID, verb, resourceName, ddPath("command", stageKey, idx))
			entry["stageName"] = stageKey
			entry["stageOrdinal"] = stageOrdinal
			entry["stageAlias"] = stageAlias
			entry["baseImage"] = baseImage
			entry["instructionIndex"] = idx
			setEvalScope(entry, "source", docID)
			setRelScope(entry, "stage", stageScope)
			addEntry(index, verb, resourceName, entry)
		}
	}
}

type dockerStage struct {
	key       string
	commands  []interface{}
	firstLine int
}

func collectDockerStages(commands map[string]interface{}) []dockerStage {
	stages := make([]dockerStage, 0, len(commands))
	for stageKey, stageRaw := range commands {
		if isInternalKey(stageKey) {
			continue
		}
		stage, ok := stageRaw.([]interface{})
		if !ok {
			continue
		}
		stages = append(stages, dockerStage{
			key:       stageKey,
			commands:  stage,
			firstLine: dockerStageFirstLine(stage),
		})
	}
	sort.Slice(stages, func(i, j int) bool {
		if stages[i].firstLine != stages[j].firstLine && stages[i].firstLine > 0 && stages[j].firstLine > 0 {
			return stages[i].firstLine < stages[j].firstLine
		}
		return stages[i].key < stages[j].key
	})
	return stages
}

func dockerStageFirstLine(stage []interface{}) int {
	if len(stage) == 0 {
		return 0
	}
	firstCommand, ok := asMap(stage[0])
	if !ok {
		return 0
	}
	if line, ok := firstCommand["_dd_line"].(int); ok && line > 0 {
		return line
	}
	if line, ok := firstCommand["_dd_line"].(float64); ok {
		return int(line)
	}
	return 0
}

func dockerStageIdentity(stage string) (baseImage, alias string) {
	parts := strings.Fields(stage)
	if len(parts) == 0 {
		return "", ""
	}
	baseImage = parts[0]
	if len(parts) >= 3 && strings.EqualFold(parts[len(parts)-2], "as") {
		alias = parts[len(parts)-1]
	}
	return baseImage, alias
}
