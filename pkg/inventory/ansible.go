/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import "github.com/DataDog/datadog-iac-scanner/pkg/model"

const platformAnsible = "ansible"

var ansibleTaskLists = []string{"tasks", "pre_tasks", "post_tasks", "handlers"}

var ansibleBlockLists = []string{"block", "rescue", "always"}

// ansibleDirectives are task keywords that are not module names.
// The invoked module is the first non-directive key of a task mapping.
var ansibleDirectives = map[string]struct{}{
	"name": {}, "when": {}, "become": {}, "become_user": {}, "become_method": {},
	"become_flags": {}, "become_exe": {}, "register": {}, "loop": {}, "loop_control": {},
	"with_items": {}, "with_dict": {}, "with_fileglob": {}, "with_together": {},
	"with_subelements": {}, "with_nested": {}, "with_sequence": {}, "with_first_found": {},
	"with_random_choice": {}, "until": {}, "retries": {}, "delay": {}, "notify": {},
	"tags": {}, "vars": {}, "environment": {}, "delegate_to": {}, "delegate_facts": {},
	"run_once": {}, "ignore_errors": {}, "ignore_unreachable": {}, "changed_when": {},
	"failed_when": {}, "check_mode": {}, "diff": {}, "no_log": {}, "args": {},
	"async": {}, "poll": {}, "throttle": {}, "timeout": {}, "any_errors_fatal": {},
	"block": {}, "rescue": {}, "always": {}, "listen": {}, "connection": {}, "port": {},
	"remote_user": {}, "module_defaults": {}, "collections": {}, "action": {},
	"local_action": {},
}

type ansibleWalker struct{}

func (ansibleWalker) Platform() string { return platformAnsible }

func (ansibleWalker) Kinds() []model.FileKind {
	return []model.FileKind{model.KindYAML, model.KindYML}
}

// Walk handles playbook files only (top-level list wrapped in a "playbooks"
// key by the YAML parser). Role task files (bare YAML lists without a
// "playbooks" key) are not supported and will return handled=false.
func (ansibleWalker) Walk(filePath string, doc model.Document) ([]Resource, bool) {
	plays, ok := doc["playbooks"].([]interface{})
	if !ok || len(plays) == 0 {
		return nil, false
	}

	var resources []Resource
	for _, p := range plays {
		play, ok := toMap(p)
		if !ok {
			continue
		}
		for _, key := range ansibleTaskLists {
			if tasks, ok := play[key].([]interface{}); ok {
				resources = append(resources, walkAnsibleTasks(filePath, tasks)...)
			}
		}
	}
	// Return handled=true even when resources is nil so no other walker
	// attempts to claim a playbook file that has plays but no tasks.
	return resources, true
}

func walkAnsibleTasks(filePath string, tasks []interface{}) []Resource {
	var resources []Resource
	for _, t := range tasks {
		task, ok := toMap(t)
		if !ok {
			continue
		}

		for _, blockKey := range ansibleBlockLists {
			if nested, ok := task[blockKey].([]interface{}); ok {
				resources = append(resources, walkAnsibleTasks(filePath, nested)...)
			}
		}

		module := ansibleModule(task)
		if module == "" {
			continue
		}
		name, _ := task["name"].(string)
		start, end := lineBounds(task)
		resources = append(resources, Resource{
			Platform:   platformAnsible,
			BlockType:  BlockTask,
			Type:       module,
			Name:       name,
			File:       filePath,
			StartLine:  start,
			EndLine:    end,
			Attributes: attrsFromBody(task),
		})
	}
	return resources
}

// ansibleModule returns the module name by picking the first non-directive key
// in alphabetical order. This is a heuristic: tasks with multiple non-directive
// keys (e.g. module + args) may not resolve correctly, but in practice the
// module is the only non-directive key for well-formed tasks.
func ansibleModule(task map[string]interface{}) string {
	for _, k := range sortedKeys(task) {
		if _, isDirective := ansibleDirectives[k]; isDirective {
			continue
		}
		return k
	}
	return ""
}
