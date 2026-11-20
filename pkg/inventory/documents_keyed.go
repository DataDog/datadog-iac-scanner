/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"gopkg.in/yaml.v3"
)

// Platform values of the keyed rows, the values findings carry.
const (
	PlatformCloudFormation = "cloudformation"
	PlatformDockerCompose  = "dockercompose"
	PlatformCICD           = "cicd"
	PlatformAnsible        = "ansible"
)

// keyedRows returns one row per entry of a top-level collection of a
// document, such as CloudFormation Resources or Compose services. An entry
// spans from its key to the line before the next entry, or to the document's
// end for the last one.
func (e *documentEnumerator) keyedRows(
	f *model.FileMetadata, index int, collection string,
	newRow func(key string, value interface{}) (Resource, bool),
) []Resource {
	entries, _ := f.Document[collection].(map[string]interface{})
	if len(entries) == 0 {
		return nil
	}
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	node, doc, found := e.documentNode(f, index)
	collectionLine := 1
	var spans map[string]lineRange
	if found {
		if keyNode, value := mappingEntry(node, collection); value != nil {
			collectionLine = keyNode.Line
			lines := e.yamlFile(f).lines
			// The collection ends before the next top-level key, so that its
			// last entry does not take the sections after it.
			bound := sectionEnd(childSpans(node, doc.end, lines), collection, doc.end)
			spans = childSpans(value, bound, lines)
		}
	}

	rows := make([]Resource, 0, len(keys))
	for _, key := range keys {
		// A key the file spells is an entry, whatever its name.
		if _, spelled := spans[key]; !spelled && isScannerKey(key) {
			continue
		}
		row, ok := newRow(key, entries[key])
		if !ok {
			continue
		}
		row.File = f.FilePath
		row.Completeness = CompletenessComplete
		row.searchKeyPrefix = collection + "." + searchKeySegment(key)
		if span, ok := spans[key]; ok {
			row.LineStart, row.LineEnd = span.start, span.end
		} else {
			// An entry the file does not spell, such as one a Compose
			// override adds, is placed at its collection.
			row.LineStart = collectionLine
		}
		rows = append(rows, row)
	}
	return rows
}

// mappingEntry returns the key and value nodes of key in a mapping node.
func mappingEntry(node *yaml.Node, key string) (keyNode, value *yaml.Node) {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i], node.Content[i+1]
		}
	}
	return nil, nil
}

// childSpans returns the line range of each entry of a mapping node, by key:
// from the key to the line before the next key, the last one to bound.
func childSpans(mapping *yaml.Node, bound int, lines []string) map[string]lineRange {
	spans := make(map[string]lineRange)
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return spans
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		start := mapping.Content[i].Line
		next := bound + 1
		if i+3 < len(mapping.Content) {
			next = mapping.Content[i+2].Line
		}
		spans[mapping.Content[i].Value] = lineRange{start: start, end: trimEnd(start, next-1, lines)}
	}
	return spans
}

// itemSpans returns the line range of each item of a sequence node: from
// the item to the line before the next item, the last one to bound.
func itemSpans(sequence *yaml.Node, bound int, lines []string) []lineRange {
	if sequence == nil || sequence.Kind != yaml.SequenceNode {
		return nil
	}
	spans := make([]lineRange, len(sequence.Content))
	for i, item := range sequence.Content {
		next := bound + 1
		if i+1 < len(sequence.Content) {
			next = sequence.Content[i+1].Line
		}
		spans[i] = lineRange{start: item.Line, end: trimEnd(item.Line, next-1, lines)}
	}
	return spans
}

// trimEnd moves end back over blank, comment and marker lines.
func trimEnd(start, end int, lines []string) int {
	end = min(end, len(lines))
	for end > start && isYAMLFiller(lines[end-1]) {
		end--
	}
	return max(end, start)
}

// searchKeySegment writes a key as search keys do: within {{ }} when it holds
// a character that separates or qualifies path segments.
func searchKeySegment(key string) string {
	if strings.ContainsAny(key, ".=/") {
		return "{{" + key + "}}"
	}
	return key
}

// isScannerKey reports a key the scanner may add to a document: its line
// information or the parsed expressions of a workflow. It applies to the keys
// the file does not spell: a job ID can be _lint, _dd_build or even
// _parsed_expressions_release.
func isScannerKey(key string) bool {
	return key == "_dd_lines" || strings.HasPrefix(key, "_parsed_expressions_")
}

func cloudFormationRow(key string, value interface{}) (Resource, bool) {
	if strings.HasPrefix(key, "Fn::ForEach::") {
		// A loop the parser could not expand: not a resource.
		return Resource{}, false
	}
	resource, _ := value.(map[string]interface{})
	typ, _ := resource["Type"].(string)
	if typ == "" {
		return Resource{}, false
	}
	return Resource{
		ResourcePath: key,
		Platform:     PlatformCloudFormation,
		ResourceType: typ,
		ResourceName: cloudFormationName(key, typ, resource),
		Provider:     "aws",
	}, true
}

// cloudFormationName returns the resource's literal name property, such as
// BucketName for an AWS::S3::Bucket, else its logical ID.
func cloudFormationName(logicalID, typ string, resource map[string]interface{}) string {
	properties, _ := resource["Properties"].(map[string]interface{})
	kind := typ[strings.LastIndex(typ, ":")+1:]
	for _, property := range []string{kind + "Name", "Name"} {
		if name, ok := properties[property].(string); ok && name != "" {
			return name
		}
	}
	return logicalID
}

func composeServiceRow(key string, _ interface{}) (Resource, bool) {
	return Resource{
		ResourcePath: "services." + key,
		Platform:     PlatformDockerCompose,
		ResourceType: "docker_compose_service",
		ResourceName: key,
	}, true
}

func workflowJobRow(key string, _ interface{}) (Resource, bool) {
	return Resource{
		ResourcePath: "jobs." + key,
		Platform:     PlatformCICD,
		ResourceType: "github_actions_job",
		ResourceName: key,
	}, true
}

// Lists of tasks of an Ansible play, which also name the directories of a
// role's task files.
const (
	ansibleTasks    = "tasks"
	ansibleHandlers = "handlers"
)

// ansibleTaskSections are the lists of tasks of a play, in run order.
var ansibleTaskSections = []string{"pre_tasks", ansibleTasks, "post_tasks", ansibleHandlers}

// ansiblePlayKeys mark a playbook's items as plays rather than tasks.
var ansiblePlayKeys = append([]string{"hosts", "import_playbook", "roles"}, ansibleTaskSections...)

// ansibleBlockSections are the lists of tasks of a block.
var ansibleBlockSections = []string{"block", "rescue", "always"}

// ansibleKeywords are the task keys that are not its module.
var ansibleKeywords = map[string]bool{
	"name": true, "when": true, "become": true, "become_user": true, "become_method": true,
	"become_flags": true, "register": true, "loop": true, "loop_control": true, "tags": true,
	"vars": true, "notify": true, "listen": true, "ignore_errors": true, "ignore_unreachable": true,
	"changed_when": true, "failed_when": true, "delegate_to": true, "delegate_facts": true,
	"environment": true, "args": true, "until": true, "retries": true, "delay": true,
	"no_log": true, "run_once": true, "check_mode": true, "diff": true, "any_errors_fatal": true,
	"connection": true, "collections": true, "module_defaults": true, "throttle": true,
	"timeout": true, "debugger": true, "async": true, "poll": true, "remote_user": true,
	"port": true, "action": true, "local_action": true,
}

// ansibleRows returns one row per task of a playbook or task file, across
// every play and its pre_tasks, tasks, post_tasks and handlers, blocks
// included. A list of mappings with no play is a task file only under a
// tasks or handlers directory, as in a role: the scanner classifies many
// other YAML lists as Ansible.
func (e *documentEnumerator) ansibleRows(f *model.FileMetadata, index int) []Resource {
	items, _ := f.Document["playbooks"].([]interface{})
	if len(items) == 0 {
		return nil
	}
	node, doc, found := e.documentNode(f, index)
	if !found {
		node = nil
	}
	lines := e.yamlFile(f).lines
	var rows []Resource
	if !isAnsiblePlaybook(items) {
		if !isAnsibleTaskFile(f.FilePath) {
			return nil
		}
		e.addAnsibleTasks(&rows, f, ansibleTasks, items, node, doc.end, lines)
		return rows
	}
	plays := itemSpans(node, doc.end, lines)
	for i, item := range items {
		play, _ := item.(map[string]interface{})
		var playNode *yaml.Node
		bound := doc.end
		if node != nil && i < len(node.Content) {
			playNode, bound = node.Content[i], plays[i].end
		}
		sections := childSpans(playNode, bound, lines)
		for _, section := range ansibleTaskSections {
			tasks, _ := play[section].([]interface{})
			if len(tasks) == 0 {
				continue
			}
			_, sectionNode := mappingEntry(playNode, section)
			e.addAnsibleTasks(&rows, f, fmt.Sprintf("plays[%d].%s", i, section), tasks, sectionNode,
				sectionEnd(sections, section, bound), lines)
		}
	}
	return rows
}

func isAnsibleTaskFile(path string) bool {
	for _, dir := range strings.Split(filepath.ToSlash(filepath.Dir(path)), "/") {
		if dir == ansibleTasks || dir == ansibleHandlers {
			return true
		}
	}
	return false
}

func isAnsiblePlaybook(items []interface{}) bool {
	for _, item := range items {
		m, _ := item.(map[string]interface{})
		for _, key := range ansiblePlayKeys {
			if _, ok := m[key]; ok {
				return true
			}
		}
	}
	return false
}

func (e *documentEnumerator) addAnsibleTasks(
	rows *[]Resource, f *model.FileMetadata, prefix string, tasks []interface{},
	sequence *yaml.Node, bound int, lines []string,
) {
	spans := itemSpans(sequence, bound, lines)
	for j, item := range tasks {
		task, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		path := fmt.Sprintf("%s[%d]", prefix, j)
		span := lineRange{start: 1}
		var taskNode *yaml.Node
		if j < len(spans) {
			span, taskNode = spans[j], sequence.Content[j]
		}
		if nested := e.addAnsibleBlock(rows, f, path, task, taskNode, span.end, lines); nested {
			continue
		}
		module := ansibleModule(task)
		name, _ := task["name"].(string)
		*rows = append(*rows, Resource{
			ResourcePath: path,
			Platform:     PlatformAnsible,
			ResourceType: module,
			ResourceName: firstNonEmpty(name, module),
			File:         f.FilePath,
			LineStart:    span.start,
			LineEnd:      span.end,
			Completeness: CompletenessComplete,
		})
	}
}

// addAnsibleBlock lists the tasks of a block and reports whether task is one.
func (e *documentEnumerator) addAnsibleBlock(
	rows *[]Resource, f *model.FileMetadata, path string, task map[string]interface{},
	taskNode *yaml.Node, bound int, lines []string,
) bool {
	isBlock := false
	sections := childSpans(taskNode, bound, lines)
	for _, section := range ansibleBlockSections {
		tasks, ok := task[section].([]interface{})
		if !ok {
			continue
		}
		isBlock = true
		_, sectionNode := mappingEntry(taskNode, section)
		e.addAnsibleTasks(rows, f, path+"."+section, tasks, sectionNode, sectionEnd(sections, section, bound), lines)
	}
	return isBlock
}

// sectionEnd is where the list under key ends: before the next key of its
// mapping.
func sectionEnd(spans map[string]lineRange, key string, bound int) int {
	if span, ok := spans[key]; ok {
		return span.end
	}
	return bound
}

// ansibleModule returns the module a task calls: the one its action or
// local_action names, else its first key, in sorted order, that is not a
// task keyword.
func ansibleModule(task map[string]interface{}) string {
	for _, key := range []string{"action", "local_action"} {
		if module := actionModule(task[key]); module != "" {
			return module
		}
	}
	keys := make([]string, 0, len(task))
	for key := range task {
		if !ansibleKeywords[key] && !strings.HasPrefix(key, "with_") && !strings.HasPrefix(key, "_") {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}

// actionModule returns the module an action or local_action names: the
// first word of its string form, or the module key of its mapping form.
func actionModule(action interface{}) string {
	switch a := action.(type) {
	case string:
		if fields := strings.Fields(a); len(fields) > 0 {
			return fields[0]
		}
	case map[string]interface{}:
		if module, ok := a["module"].(string); ok {
			return module
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
