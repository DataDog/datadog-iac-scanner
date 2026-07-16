/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resourceindex

import (
	"fmt"
	"strings"
)

func indexAnsibleDoc(index, doc map[string]interface{}, docID string) {
	if groups, ok := doc["groups"].(map[string]interface{}); ok {
		for groupName, groupBody := range groups {
			if isInternalKey(groupName) {
				continue
			}
			addEntry(index, "ansible.config", groupName,
				makeEntry(groupBody, docID, "ansible_config", groupName, ddPath("groups", groupName)))
		}
	}

	if all, ok := doc["all"]; ok {
		addEntry(index, "ansible_inventory", "inventory", makeEntry(all, docID, "ansible_inventory", "inventory", ddPath("all")))
		if inventory, ok := asMap(all); ok {
			indexAnsibleInventoryGroups(index, inventory["children"], docID, ddPath("all", "children"))
		}
	}

	playbooks, ok := doc["playbooks"].([]interface{})
	if !ok {
		return
	}

	for pbIdx, pbRaw := range playbooks {
		pb, ok := asMap(pbRaw)
		if !ok {
			continue
		}
		pbPath := ddPath("playbooks", pbIdx)
		if isBareAnsibleTask(pb) {
			indexAnsibleTask(index, pb, docID, pbPath, "", pbIdx)
			continue
		}
		pbName, _ := pb["name"].(string)
		if pbName == "" {
			pbName = fmt.Sprintf("playbook:%d", pbIdx)
		}

		playScope := fmt.Sprintf("%s:play:%d", docID, pbIdx)
		playEntry := makeEntry(pb, docID, "ansible_playbook", pbName, pbPath)
		setEntryField(playEntry, "playOrder", pbIdx)
		setEvalScope(playEntry, "play", playScope)
		setEvalScope(playEntry, "document", docID)
		setRelScope(playEntry, "document", docID)
		addEntry(index, "ansible_playbook", pbName, playEntry)

		for _, section := range []string{"pre_tasks", "tasks", "post_tasks", "handlers"} {
			tasks, ok := pb[section].([]interface{})
			if !ok {
				continue
			}
			indexAnsibleTasks(index, tasks, docID, []interface{}{"playbooks", pbIdx, section}, playScope)
		}
	}
}

func indexAnsibleInventoryGroups(
	index map[string]interface{},
	rawGroups interface{},
	docID string,
	parentPath []interface{},
) {
	groups, ok := asMap(rawGroups)
	if !ok {
		return
	}
	for groupName, rawGroup := range groups {
		if isInternalKey(groupName) {
			continue
		}
		group, ok := asMap(rawGroup)
		if !ok {
			continue
		}
		groupPath := appendPath(parentPath, groupName)
		addEntry(index, "ansible.inventory_group", groupName,
			makeEntry(group, docID, "ansible_inventory", groupName, groupPath))
		indexAnsibleInventoryGroups(index, group["children"], docID, appendPath(groupPath, "children"))
	}
}

func indexAnsibleTasks(index map[string]interface{}, tasks []interface{}, docID string, parentPath []interface{}, playScope string) {
	for taskIdx, taskRaw := range tasks {
		task, ok := asMap(taskRaw)
		if !ok {
			continue
		}
		taskPath := append(append([]interface{}{}, parentPath...), taskIdx)
		indexAnsibleTask(index, task, docID, taskPath, playScope, taskIdx)
	}
}

func indexAnsibleTask(
	index, task map[string]interface{},
	docID string,
	taskPath []interface{},
	playScope string,
	taskOrder int,
) {
	taskName := ansibleTaskName(task)
	if taskName == "" {
		taskName = fmt.Sprintf("task:%v", taskPath)
	}
	taskEntry := makeEntry(task, docID, "ansible_task", taskName, taskPath)
	setEntryField(taskEntry, "taskOrder", taskOrder)
	setEntryField(taskEntry, "taskPath", append([]interface{}(nil), taskPath...))
	taskScope := docID + ":task:" + ansiblePathString(taskPath)
	setEvalScope(taskEntry, "document", docID)
	setRelScope(taskEntry, "document", docID)
	if playScope != "" {
		setEvalScope(taskEntry, "play", playScope)
		setRelScope(taskEntry, "play", playScope)
	}
	setRelScope(taskEntry, "task", taskScope)
	addEntry(index, "ansible_task", taskName, taskEntry)
	indexAnsibleModuleTargets(index, task, docID, taskName, taskPath, playScope, taskScope, taskOrder)

	for _, group := range []string{"block", "rescue", "always"} {
		if nested, ok := task[group].([]interface{}); ok {
			indexAnsibleTasks(index, nested, docID, append(append([]interface{}{}, taskPath...), group), playScope)
		}
	}
}

func isBareAnsibleTask(value map[string]interface{}) bool {
	for _, playbookKey := range []string{"hosts", "tasks", "pre_tasks", "post_tasks", "handlers", "roles"} {
		if _, ok := value[playbookKey]; ok {
			return false
		}
	}
	for key, raw := range value {
		if _, control := ansibleTaskControlKeys[key]; !control &&
			!strings.HasPrefix(key, "with_") && !isInternalKey(key) &&
			isAnsibleModuleValue(raw) {
			return true
		}
	}
	_, hasAction := value["action"]
	return hasAction
}

var ansibleTaskControlKeys = map[string]struct{}{
	"name":             {},
	"Name":             {},
	"action":           {},
	"args":             {},
	"when":             {},
	"vars":             {},
	"tags":             {},
	"register":         {},
	"become":           {},
	"become_user":      {},
	"become_method":    {},
	"loop":             {},
	"loop_control":     {},
	"environment":      {},
	"notify":           {},
	"changed_when":     {},
	"failed_when":      {},
	"ignore_errors":    {},
	"delegate_to":      {},
	"run_once":         {},
	"until":            {},
	"retries":          {},
	"delay":            {},
	"check_mode":       {},
	"any_errors_fatal": {},
	"collections":      {},
	"block":            {},
	"rescue":           {},
	"always":           {},
}

func indexAnsibleModuleTargets(
	index map[string]interface{},
	task map[string]interface{},
	docID, taskName string,
	taskPath []interface{},
	playScope, taskScope string,
	taskOrder int,
) {
	invocations := ansibleModuleInvocations(task)
	for _, invocation := range invocations {
		moduleName := invocation.name
		rawArguments := invocation.arguments
		if _, control := ansibleTaskControlKeys[moduleName]; control ||
			strings.HasPrefix(moduleName, "with_") || isInternalKey(moduleName) {
			continue
		}

		canonicalModuleName := canonicalAnsibleModule(moduleName)
		arguments := ansibleArguments(task["args"])
		for key, value := range ansibleArguments(rawArguments) {
			arguments[key] = value
		}
		arguments["moduleName"] = canonicalModuleName
		arguments["originalModuleName"] = moduleName
		arguments["taskName"] = taskName
		arguments["taskOrder"] = taskOrder
		arguments["taskPath"] = append([]interface{}(nil), taskPath...)

		resourceName := firstNonEmptyString(arguments, ansibleModuleNameKey(canonicalModuleName))
		if resourceName == "" {
			resourceName = taskName
		}
		if resourceName == "" {
			resourceName = canonicalModuleName
		}

		modulePath := appendPath(taskPath, invocation.path...)
		addAnsibleModuleEntry(index, arguments, docID, canonicalModuleName, resourceName,
			modulePath, playScope, taskScope, "ansible.module")
		addAnsibleModuleEntry(index, arguments, docID, canonicalModuleName, resourceName,
			modulePath, playScope, taskScope, canonicalModuleName)
	}
}

type ansibleModuleInvocation struct {
	name      string
	arguments interface{}
	path      []interface{}
}

func ansibleModuleInvocations(task map[string]interface{}) []ansibleModuleInvocation {
	invocations := make([]ansibleModuleInvocation, 0, 1)
	for moduleName, rawArguments := range task {
		if _, control := ansibleTaskControlKeys[moduleName]; control ||
			strings.HasPrefix(moduleName, "with_") || isInternalKey(moduleName) ||
			!isAnsibleModuleValue(rawArguments) {
			continue
		}
		invocations = append(invocations, ansibleModuleInvocation{
			name: moduleName, arguments: rawArguments, path: []interface{}{moduleName},
		})
	}
	if action, ok := task["action"]; ok {
		if invocation, ok := ansibleActionInvocation(action); ok {
			invocations = append(invocations, invocation)
		}
	}
	return invocations
}

func ansibleActionInvocation(action interface{}) (ansibleModuleInvocation, bool) {
	if actionMap, ok := asMap(action); ok {
		moduleName := firstNonEmptyString(actionMap, "module", "__ansible_module__")
		if moduleName == "" {
			for candidate, rawArguments := range actionMap {
				if candidate == "args" || isInternalKey(candidate) || !isAnsibleModuleValue(rawArguments) {
					continue
				}
				return ansibleModuleInvocation{
					name: candidate, arguments: rawArguments, path: []interface{}{"action", candidate},
				}, true
			}
			return ansibleModuleInvocation{}, false
		}
		arguments := ansibleArguments(actionMap["args"])
		for key, value := range actionMap {
			arguments[key] = value
		}
		delete(arguments, "module")
		delete(arguments, "__ansible_module__")
		delete(arguments, "args")
		return ansibleModuleInvocation{name: moduleName, arguments: arguments, path: []interface{}{"action"}}, true
	}
	actionText, ok := action.(string)
	if !ok {
		return ansibleModuleInvocation{}, false
	}
	words, ok := splitAnsibleWords(actionText)
	if !ok || len(words) == 0 {
		return ansibleModuleInvocation{}, false
	}
	moduleName := words[0]
	if key, value, found := strings.Cut(moduleName, "="); found && key == "module" {
		moduleName = value
		words = words[1:]
	} else {
		words = words[1:]
	}
	return ansibleModuleInvocation{
		name: moduleName, arguments: ansibleKeyValueArguments(words), path: []interface{}{"action"},
	}, moduleName != ""
}

func ansibleArguments(raw interface{}) map[string]interface{} {
	if argumentMap, ok := asMap(raw); ok {
		return cloneMap(argumentMap)
	}
	if text, ok := raw.(string); ok {
		words, valid := splitAnsibleWords(text)
		if valid {
			arguments := ansibleKeyValueArguments(words)
			if len(arguments) > 0 {
				return arguments
			}
		}
	}
	if raw == nil {
		return make(map[string]interface{})
	}
	return map[string]interface{}{"value": raw}
}

func splitAnsibleWords(value string) ([]string, bool) {
	words := make([]string, 0)
	var word strings.Builder
	var quote rune
	escaped := false
	flush := func() {
		if word.Len() > 0 {
			words = append(words, word.String())
			word.Reset()
		}
	}
	for _, current := range value {
		if escaped {
			word.WriteRune(current)
			escaped = false
			continue
		}
		if current == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if current == quote {
				quote = 0
			} else {
				word.WriteRune(current)
			}
			continue
		}
		switch current {
		case '\'', '"':
			quote = current
		case ' ', '\t', '\r', '\n':
			flush()
		default:
			word.WriteRune(current)
		}
	}
	if escaped {
		word.WriteRune('\\')
	}
	if quote != 0 {
		return nil, false
	}
	flush()
	return words, true
}

func ansibleKeyValueArguments(words []string) map[string]interface{} {
	arguments := make(map[string]interface{})
	for _, word := range words {
		key, value, ok := strings.Cut(word, "=")
		if ok && key != "" {
			arguments[key] = value
		}
	}
	return arguments
}

func isAnsibleModuleValue(value interface{}) bool {
	if _, ok := asMap(value); ok {
		return true
	}
	switch value.(type) {
	case string, nil:
		return true
	default:
		return false
	}
}

func addAnsibleModuleEntry(
	index map[string]interface{},
	arguments map[string]interface{},
	docID, canonicalModuleName, resourceName string,
	modulePath []interface{},
	playScope, taskScope, bucket string,
) {
	moduleEntry := makeEntry(arguments, docID, canonicalModuleName, resourceName, modulePath)
	setEvalScope(moduleEntry, "document", docID)
	setRelScope(moduleEntry, "document", docID)
	if playScope != "" {
		setEvalScope(moduleEntry, "play", playScope)
		setRelScope(moduleEntry, "play", playScope)
	}
	setRelScope(moduleEntry, "task", taskScope)
	addEntry(index, bucket, resourceName, moduleEntry)
}

func ansibleTaskName(task map[string]interface{}) string {
	for _, key := range []string{"name", "Name"} {
		if n, ok := task[key].(string); ok && n != "" {
			return n
		}
	}
	return ""
}

func ansiblePathString(path []interface{}) string {
	parts := make([]string, len(path))
	for i, p := range path {
		parts[i] = fmt.Sprintf("%v", p)
	}
	return strings.Join(parts, "/")
}
