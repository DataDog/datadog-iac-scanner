/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package occurrence

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/cicd/gitlab"
	"github.com/DataDog/datadog-iac-scanner/pkg/platforms"
	"gopkg.in/yaml.v3"
)

// keyedOccurrences records each entry of a top-level collection.
func (e *documentEnumerator) keyedOccurrences(
	f *model.FileMetadata, index int, collection string, parserKey parserKeys,
	newRow func(key string, value interface{}) (model.ResourceOccurrence, bool),
) []model.ResourceOccurrence {
	rows, _ := e.keyedCollection(f, index, collection, parserKey, newRow)
	return rows
}

func (e *documentEnumerator) keyedCollection(
	f *model.FileMetadata, index int, collection string, parserKey parserKeys,
	newRow func(key string, value interface{}) (model.ResourceOccurrence, bool),
) (rows []model.ResourceOccurrence, spans map[string]lineRange) {
	entries, _ := f.Document[collection].(map[string]interface{})
	if len(entries) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	node, doc, found := e.documentNode(f, index)
	collectionLine := 1
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

	rows = make([]model.ResourceOccurrence, 0, len(keys))
	for _, key := range keys {
		if parserKey(key, entries) {
			continue
		}
		row, ok := newRow(key, entries[key])
		if !ok {
			continue
		}
		row.File = f.FilePath
		row.StructuralPath = model.SourcePath{{Key: collection}, {Key: key}}
		if span, ok := spans[key]; ok {
			row.Source = lineSource(span.start, span.end)
			row.LegacySource = row.Source
		} else {
			// An entry the file does not spell, such as one a Compose
			// override adds, is placed at its collection.
			row.Source = lineSource(collectionLine, 0)
			if f.Platform == platforms.CloudFormation {
				row.LegacyCollectionLine = collectionLine
			}
		}
		rows = append(rows, row)
	}
	return rows, spans
}

func (e *documentEnumerator) cloudFormationOccurrences(f *model.FileMetadata, index int) []model.ResourceOccurrence {
	rows, spans := e.keyedCollection(f, index, "Resources", lineInfoKey, cloudFormationOccurrence)
	loops := make(map[int]lineRange)
	for key, span := range spans {
		if strings.HasPrefix(key, "Fn::ForEach::") {
			if prev, ok := loops[span.start]; ok {
				span.end = min(span.end, prev.end)
			}
			loops[span.start] = span
		}
	}
	if len(loops) == 0 || len(rows) == 0 {
		return rows
	}
	// The expansion copies the outer loop's key line to every generated ID.
	// Keep its collection line for legacy results and display the loop span.
	annotated := f.ShallowCopy()
	defer annotated.DiscardLineInfoDocument()
	_ = annotated.UseLineInfoDocument(e.ctx, func(doc map[string]interface{}) error {
		resources, _ := doc["Resources"].(map[string]interface{})
		lines, _ := resources["_dd_lines"].(map[string]*model.LineObject)
		for i := range rows {
			row := &rows[i]
			if _, written := spans[row.ResourcePath]; written {
				continue
			}
			if line := lines["_dd_"+row.ResourcePath]; line != nil {
				if span, ok := loops[line.Line]; ok {
					row.Source = lineSource(span.start, span.end)
				}
			}
		}
		return nil
	})
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

// parserKeys reports a key of a collection that its platform's parser added,
// rather than an entry the configuration declares. Any other key is an
// entry, whatever its name and however it got there, a YAML merge included.
type parserKeys func(key string, entries map[string]interface{}) bool

// lineInfoKey reports the line information every YAML and JSON parser adds.
func lineInfoKey(key string, _ map[string]interface{}) bool {
	return key == "_dd_lines"
}

// parsedExpressionsPrefix names the parsed form of a workflow value's
// expressions, which the workflow parser stores next to the value.
const parsedExpressionsPrefix = "_parsed_expressions_"

// workflowParserKey reports the keys the workflow parser adds: line
// information, and _parsed_expressions_<key> next to a key whose string or
// list value holds expressions. A job ID can still be _lint, _dd_build or
// _parsed_expressions_release.
func workflowParserKey(key string, entries map[string]interface{}) bool {
	if lineInfoKey(key, entries) {
		return true
	}
	name, ok := strings.CutPrefix(key, parsedExpressionsPrefix)
	if !ok {
		return false
	}
	switch entries[name].(type) {
	case string, []interface{}:
		return true
	}
	return false
}

func cloudFormationOccurrence(key string, value interface{}) (model.ResourceOccurrence, bool) {
	if strings.HasPrefix(key, "Fn::ForEach::") {
		// A loop the parser could not expand: not a resource.
		return model.ResourceOccurrence{}, false
	}
	resource, _ := value.(map[string]interface{})
	typ, _ := resource["Type"].(string)
	if typ == "" {
		return model.ResourceOccurrence{}, false
	}
	return model.ResourceOccurrence{
		ResourcePath: key,
		Platform:     platforms.CloudFormation,
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

func composeServiceOccurrence(key string, _ interface{}) (model.ResourceOccurrence, bool) {
	return model.ResourceOccurrence{
		ResourcePath: "services." + key,
		Platform:     platforms.DockerCompose,
		ResourceType: "docker_compose_service",
		ResourceName: key,
	}, true
}

func workflowJobOccurrence(key string, _ interface{}) (model.ResourceOccurrence, bool) {
	return model.ResourceOccurrence{
		ResourcePath: "jobs." + key,
		Platform:     platforms.CICD,
		ResourceType: "github_actions_job",
		ResourceName: key,
	}, true
}

// cicdOccurrences records jobs from GitHub Actions workflows (under "jobs")
// and executable top-level jobs from GitLab CI pipelines.
func (e *documentEnumerator) cicdOccurrences(f *model.FileMetadata, index int) []model.ResourceOccurrence {
	isGitLabPath := gitlab.IsConfigFileName(f.FilePath) || gitlab.IsCIDirPath(f.FilePath)
	if _, hasJobs := f.Document["jobs"].(map[string]interface{}); hasJobs &&
		(f.DocumentDialect != gitlab.Dialect && !gitlab.ShouldParse([]byte(f.OriginalData), f.FilePath)) {
		return e.keyedOccurrences(f, index, "jobs", workflowParserKey, workflowJobOccurrence)
	}
	if gitlab.IsSpecHeaderDocument(f.Document) {
		return nil
	}
	if !isGitLabPath && f.DocumentDialect != gitlab.Dialect && !gitlab.IsDocument(f.Document) {
		return nil
	}
	return e.gitlabJobOccurrences(f, index)
}

func (e *documentEnumerator) gitlabJobOccurrences(f *model.FileMetadata, index int) []model.ResourceOccurrence {
	if f.SourceDocumentIndexKnown {
		index = f.SourceDocumentIndex
	}
	keys := make([]string, 0, len(f.Document))
	for key, val := range f.Document {
		if gitlab.IsExecutableJob(key, val) {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Strings(keys)

	var spans map[string]lineRange
	if f.LineOverlay == nil {
		if node, doc, found := e.documentNode(f, index); found {
			spans = childSpans(node, doc.end, e.yamlFile(f).lines)
		}
	}
	byStart := make(map[int]lineRange, len(spans))
	for _, span := range spans {
		byStart[span.start] = span
	}

	rows := make([]model.ResourceOccurrence, 0, len(keys))
	var unmatched []int
	for _, key := range keys {
		row := model.ResourceOccurrence{
			ResourcePath:   key,
			Platform:       platforms.CICD,
			ResourceType:   "gitlab_ci_job",
			ResourceName:   key,
			File:           f.FilePath,
			StructuralPath: model.SourcePath{{Key: key}},
		}
		position := f.LineOverlay.LookupSource([]string{key})
		if position.Snapshot != nil {
			if source := f.SourceFiles[position.Snapshot]; source != nil && source.SourceExcluded {
				continue
			}
			start, end := position.Snapshot.DeclarationSpan(position.DocumentIndex, position.Line)
			row.File = position.Snapshot.Path
			row.Source = lineSource(start, end)
			row.LegacySource = row.Source
		} else if span, ok := spans[key]; ok {
			row.Source = lineSource(span.start, span.end)
			row.LegacySource = row.Source
		} else {
			unmatched = append(unmatched, len(rows))
		}
		rows = append(rows, row)
	}

	if len(unmatched) > 0 {
		e.fillGitLabInterpolatedSpans(f, rows, unmatched, byStart)
	}
	return rows
}

// fillGitLabInterpolatedSpans matches jobs whose YAML key was rewritten by
// input interpolation back to their written source span via preserved
// `_dd_lines` markers, falling back to firstKeyLine when unavailable.
func (e *documentEnumerator) fillGitLabInterpolatedSpans(
	f *model.FileMetadata,
	rows []model.ResourceOccurrence,
	unmatched []int,
	byStart map[int]lineRange,
) {
	lineByKey := e.documentRootKeyLines(f)
	for _, idx := range unmatched {
		row := &rows[idx]
		if start := lineByKey[row.ResourcePath]; start > 0 {
			if span, ok := byStart[start]; ok {
				row.Source = lineSource(span.start, span.end)
				row.LegacySource = row.Source
				continue
			}
			row.Source = lineSource(start, 0)
			continue
		}
		row.Source = lineSource(e.firstKeyLine(f), 0)
	}
}

func (e *documentEnumerator) documentRootKeyLines(f *model.FileMetadata) map[string]int {
	if out := extractRootKeyLines(f.Document); len(out) > 0 {
		return out
	}
	annotated := f.ShallowCopy()
	defer annotated.DiscardLineInfoDocument()
	var out map[string]int
	_ = annotated.UseLineInfoDocument(e.ctx, func(doc map[string]interface{}) error {
		out = extractRootKeyLines(doc)
		return nil
	})
	return out
}

func extractRootKeyLines(doc map[string]interface{}) map[string]int {
	if doc == nil {
		return nil
	}
	raw, ok := doc["_dd_lines"]
	if !ok {
		return nil
	}
	out := make(map[string]int)
	switch lines := raw.(type) {
	case map[string]*model.LineObject:
		for k, v := range lines {
			if name, ok := strings.CutPrefix(k, "_dd_"); ok && v != nil && v.Line > 0 {
				out[name] = v.Line
			}
		}
	case map[string]interface{}:
		for k, v := range lines {
			if name, ok := strings.CutPrefix(k, "_dd_"); ok {
				if line := lineObjectLine(v); line > 0 {
					out[name] = line
				}
			}
		}
	}
	return out
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

// ansibleKeywords are the task keys that are not its module: the Task
// keywords of the Ansible playbook keywords reference
// (https://docs.ansible.com/projects/ansible/latest/reference_appendices/playbooks_keywords.html#task),
// which also lists with_<lookup_plugin>, and listen, which handlers add.
// Keep it in step with that page.
var ansibleKeywords = map[string]bool{
	"action": true, "any_errors_fatal": true, "args": true, "async": true,
	"become": true, "become_exe": true, "become_flags": true, "become_method": true, "become_user": true,
	"changed_when": true, "check_mode": true, "collections": true, "connection": true,
	"debugger": true, "delay": true, "delegate_facts": true, "delegate_to": true, "diff": true,
	"environment": true, "failed_when": true, "ignore_errors": true, "ignore_unreachable": true,
	"local_action": true, "loop": true, "loop_control": true, "module_defaults": true,
	"name": true, "no_log": true, "notify": true, "poll": true, "port": true,
	"register": true, "remote_user": true, "retries": true, "run_once": true,
	"tags": true, "throttle": true, "timeout": true, "until": true, "vars": true, "when": true,
	"listen": true,
}

// ansibleOccurrences records each task of a playbook or task file, across
// every play and its pre_tasks, tasks, post_tasks and handlers, blocks
// included. A list of mappings with no play is a task file only under a
// tasks or handlers directory, as in a role: the scanner classifies many
// other YAML lists as Ansible.
func (e *documentEnumerator) ansibleOccurrences(f *model.FileMetadata, index int) []model.ResourceOccurrence {
	items, _ := f.Document["playbooks"].([]interface{})
	if len(items) == 0 {
		return nil
	}
	node, doc, found := e.documentNode(f, index)
	if !found {
		node = nil
	}
	lines := e.yamlFile(f).lines
	var rows []model.ResourceOccurrence
	if !isAnsiblePlaybook(items) {
		if !isAnsibleTaskFile(f.FilePath) {
			return nil
		}
		e.addAnsibleTasks(&rows, f, ansibleTasks, model.SourcePath{{Key: "playbooks"}}, items, node, doc.end, lines)
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
			e.addAnsibleTasks(&rows, f, fmt.Sprintf("plays[%d].%s", i, section),
				model.SourcePath{{Key: "playbooks"}, {Index: i, IsIndex: true}, {Key: section}}, tasks, sectionNode,
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
	rows *[]model.ResourceOccurrence, f *model.FileMetadata, prefix string, base model.SourcePath, tasks []interface{},
	sequence *yaml.Node, bound int, lines []string,
) {
	spans := itemSpans(sequence, bound, lines)
	for j, item := range tasks {
		task, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		path := fmt.Sprintf("%s[%d]", prefix, j)
		structuralPath := extendPath(base, model.PathSegment{Index: j, IsIndex: true})
		span := lineRange{start: 1}
		var taskNode *yaml.Node
		if j < len(spans) {
			span, taskNode = spans[j], sequence.Content[j]
		}
		if nested := e.addAnsibleBlock(rows, f, path, structuralPath, task, taskNode, span.end, lines); nested {
			continue
		}
		module := ansibleModule(task)
		name, _ := task["name"].(string)
		*rows = append(*rows, model.ResourceOccurrence{
			ResourcePath:   path,
			Platform:       platforms.Ansible,
			ResourceType:   module,
			ResourceName:   firstNonEmpty(name, module),
			File:           f.FilePath,
			Source:         lineSource(span.start, span.end),
			StructuralPath: structuralPath,
			LegacySource:   writtenSpan(span, taskNode != nil),
		})
	}
}

// addAnsibleBlock lists the tasks of a block and reports whether task is one.
func (e *documentEnumerator) addAnsibleBlock(
	rows *[]model.ResourceOccurrence, f *model.FileMetadata, path string, base model.SourcePath, task map[string]interface{},
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
		e.addAnsibleTasks(rows, f, path+"."+section, extendPath(base, model.PathSegment{Key: section}),
			tasks, sectionNode, sectionEnd(sections, section, bound), lines)
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
