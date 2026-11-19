package engine

// A dynamic FROM can inherit configuration from an earlier local stage. The
// parser's unwritten defaults do not prove absence in that case. Contexts can
// be shared with independent stages, so uncertain contexts get private copies.
func taintUnknownDockerInheritance(facts map[string]interface{}, placeholder string, uncertain map[int]bool) {
	if len(uncertain) == 0 {
		return
	}
	contexts, _ := facts["contexts"].([]interface{})
	copies := map[int]int{}
	projectContext := func(raw interface{}) interface{} {
		index, ok := dockerFactIndex(raw)
		if !ok || index < 0 || index >= len(contexts) {
			return raw
		}
		if projected, exists := copies[index]; exists {
			return projected
		}
		original, ok := contexts[index].(map[string]interface{})
		if !ok {
			return raw
		}
		copy := cloneDockerInheritanceValue(original).(map[string]interface{})
		taintDockerInheritedContext(copy, placeholder)
		projected := len(contexts)
		contexts = append(contexts, copy)
		copies[index], copies[projected] = projected, projected
		return projected
	}
	stages, _ := facts["stages"].([]interface{})
	for index, raw := range stages {
		if !uncertain[index] {
			continue
		}
		if stage, ok := raw.(map[string]interface{}); ok {
			stage["context"] = projectContext(stage["context"])
		}
	}
	instructions, _ := facts["instructions"].([]interface{})
	for _, raw := range instructions {
		instruction, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		stage, ok := dockerFactIndex(instruction["stage"])
		if !ok || !uncertain[stage] {
			continue
		}
		instruction["context"] = projectContext(instruction["context"])
	}
	facts["contexts"] = contexts
}

func taintDockerInheritedContext(context map[string]interface{}, placeholder string) {
	for _, field := range []string{"user_set", "healthcheck_set"} {
		if context[field] == false {
			context[field] = placeholder
		}
	}
	for _, field := range []string{"user_instruction", "environment", "arguments"} {
		if index, ok := dockerFactIndex(context[field]); ok && index < 0 {
			context[field] = placeholder
		}
	}
}

func cloneDockerInheritanceValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		cloned := make(map[string]interface{}, len(typed))
		for key, child := range typed {
			cloned[key] = cloneDockerInheritanceValue(child)
		}
		return cloned
	case []interface{}:
		cloned := make([]interface{}, len(typed))
		for i, child := range typed {
			cloned[i] = cloneDockerInheritanceValue(child)
		}
		return cloned
	default:
		return value
	}
}
