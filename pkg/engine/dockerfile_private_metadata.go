package engine

// Parser bookkeeping is consumed while producing policy facts, then removed.
// Rules receive values and open inventories, without a second knownness API.
func removeDockerParserMetadata(value interface{}, placeholder string) {
	switch typed := value.(type) {
	case []interface{}:
		for _, child := range typed {
			removeDockerParserMetadata(child, placeholder)
		}
	case map[string]interface{}:
		if _, instruction := typed["parse_ok"].(bool); instruction {
			delete(typed, "error")
		}
		for _, field := range []string{"known", "complete", "shell_known", "version_known", "parse_ok"} {
			metadata, exists := typed[field]
			if !exists {
				continue
			}
			_, boolean := metadata.(bool)
			text, _ := metadata.(string)
			if boolean || text == placeholder {
				delete(typed, field)
			}
		}
		for _, child := range typed {
			removeDockerParserMetadata(child, placeholder)
		}
	}
}
