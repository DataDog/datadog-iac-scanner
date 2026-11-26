/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com) Copyright 2026 Datadog, Inc.
 */
package gitlab

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/yamlnode"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"gopkg.in/yaml.v3"
)

type conditionValue uint8

const (
	conditionUnknown conditionValue = iota
	conditionFalse
	conditionTrue
)

type existenceResult struct {
	value   conditionValue
	missing []string
}

// GitLab assumes a patterned rule matches above this comparison count. This
// belongs to the language semantics, independently of scanner resource limits.
const (
	gitlabExistenceComparisons = 50_000
	gitMetadataDir             = ".git"
)

type existencePathCount struct {
	count    int
	complete bool
}

// Rules use first-match semantics. Only guaranteed includes are merged;
// uncertainty retains the unconditional branch and marks coverage incomplete.
// A partial snapshot requests predicates that can still change the decision.
func (s *FileState) includeEnabled(entry *yaml.Node) bool {
	rules := yamlnode.MappingValue(entry, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return true
	}
	mayInclude, maySkip, fallthroughPossible := false, false, true
	var missing []string
	for _, rule := range rules.Content {
		condition := s.includeRuleCondition(rule)
		if condition.value == conditionFalse {
			continue
		}
		missing = append(missing, condition.missing...)
		when := yamlnode.MappingValue(rule, "when")
		if when != nil && when.Value == "never" {
			maySkip = true
		} else {
			mayInclude = true
		}
		if condition.value == conditionTrue {
			fallthroughPossible = false
			break
		}
	}
	maySkip = maySkip || fallthroughPossible
	if mayInclude && maySkip {
		s.uncertainIncludes = true
		if recorder, ok := s.fsys.(vfs.MissingRecorder); ok {
			for _, name := range missing {
				recorder.RecordMissing(name)
			}
		}
		return false
	}
	return mayInclude
}

// UncertainIncludes reports that the output retains the unconditional branch;
// possible conditional additions and overrides require unavailable CI context.
func (s *FileState) UncertainIncludes() bool { return s.uncertainIncludes }

func (s *FileState) includeRuleCondition(rule *yaml.Node) existenceResult {
	if rule == nil || rule.Kind != yaml.MappingNode {
		return existenceResult{value: conditionUnknown}
	}
	result := existenceResult{value: conditionTrue}
	if exists := yamlnode.MappingValue(rule, "exists"); exists != nil {
		result = s.existsCondition(exists)
		if result.value == conditionFalse {
			return result
		}
	}
	for i := 0; i+1 < len(rule.Content); i += 2 {
		if key := rule.Content[i].Value; key != "when" && key != "exists" {
			result.value = conditionUnknown
		}
	}
	return result
}

func (s *FileState) existsCondition(node *yaml.Node) existenceResult {
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value != "paths" {
				return existenceResult{value: conditionUnknown}
			}
		}
		node = yamlnode.MappingValue(node, "paths")
	}
	if node == nil || node.Kind != yaml.SequenceNode {
		return existenceResult{value: conditionUnknown}
	}
	budget := s.existenceBudget(node)
	if budget.value == conditionTrue {
		return budget
	}
	result := existenceResult{value: conditionFalse}
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			result.value = conditionUnknown
			continue
		}
		condition := s.existsPath(item.Value)
		if condition.value == conditionTrue {
			return existenceResult{value: conditionTrue}
		}
		if condition.value == conditionUnknown {
			result.value = conditionUnknown
			result.missing = append(result.missing, condition.missing...)
		}
	}
	if budget.value == conditionUnknown {
		result.value = conditionUnknown
		result.missing = append(result.missing, budget.missing...)
	}
	return result
}

func (s *FileState) existenceBudget(paths *yaml.Node) existenceResult {
	patterns, topLevel := 0, true
	for _, item := range paths.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		value := item.Value
		if strings.Contains(value, "/") || strings.Contains(value, "**") {
			topLevel = false
		}
		if !strings.Contains(value, "$") && patternedExistenceGlob(value) {
			patterns++
		}
	}
	if patterns == 0 {
		return existenceResult{value: conditionFalse}
	}
	count := s.existencePathCount(topLevel)
	if count.count > gitlabExistenceComparisons/patterns {
		return existenceResult{value: conditionTrue}
	}
	if !count.complete {
		return existenceResult{value: conditionUnknown, missing: []string{s.baseDir}}
	}
	return existenceResult{value: conditionFalse}
}

func patternedExistenceGlob(pattern string) bool {
	const meta = "*?[{"
	if !strings.ContainsAny(pattern, meta) {
		return false
	}
	// GitLab handles simple **/*.ext predicates with a suffix lookup, outside
	// the patterned-comparison allowance.
	suffix := strings.TrimPrefix(pattern, "**/*")
	return !strings.HasPrefix(suffix, ".") || strings.Contains(suffix, "/") || strings.ContainsAny(suffix, meta)
}

func (s *FileState) existencePathCount(topLevel bool) existencePathCount {
	if cached, found := s.existenceCounts[topLevel]; found {
		return cached
	}
	fsys := s.fsys
	if snapshot, ok := fsys.(*vfs.MemFS); ok {
		fsys = snapshot.Fork()
	}
	result := existencePathCount{complete: true}
	if snapshot, ok := fsys.(vfs.DirectorySnapshot); ok {
		result.complete = snapshot.DirectoryComplete(s.baseDir)
	}
	pending := []string{s.baseDir}
	for len(pending) > 0 && result.count <= gitlabExistenceComparisons && s.ctx.Err() == nil {
		dir := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		entries, err := fsys.ReadDir(dir)
		if err != nil {
			result.complete = false
			continue
		}
		for _, entry := range entries {
			if entry.Name() == gitMetadataDir {
				continue
			}
			if !Reserve(s.ctx, 1, 0) {
				break
			}
			if entry.IsDir() {
				if !topLevel {
					pending = append(pending, filepath.Join(dir, entry.Name()))
				}
			} else {
				result.count++
				if result.count > gitlabExistenceComparisons {
					break
				}
			}
		}
	}
	if s.existenceCounts == nil {
		s.existenceCounts = make(map[bool]existencePathCount)
	}
	s.existenceCounts[topLevel] = result
	return result
}

func (s *FileState) existsPath(pattern string) existenceResult {
	if s.existenceConditions == nil {
		s.existenceConditions = make(map[string]existenceResult)
	}
	if result, seen := s.existenceConditions[pattern]; seen {
		return result
	}
	result := s.probeExists(pattern)
	s.existenceConditions[pattern] = result
	return result
}

func (s *FileState) probeExists(pattern string) existenceResult {
	if strings.Contains(pattern, "$") {
		return existenceResult{value: conditionUnknown}
	}
	target, ok := s.existenceTarget(pattern)
	if !ok {
		return existenceResult{value: conditionUnknown}
	}
	directory := strings.HasSuffix(pattern, "/")
	if !strings.ContainsAny(pattern, "*?[{\\") {
		if !validGlobPrefix(strings.TrimSuffix(pattern, "/")) {
			return existenceResult{value: conditionFalse}
		}
		return s.literalExists(target, directory)
	}
	probe := *s
	if snapshot, ok := s.fsys.(*vfs.MemFS); ok {
		probe.fsys = snapshot.Fork()
	}
	glob := localGlob{
		state: &probe, matches: make(map[string]bool), directories: directory, probe: true,
	}
	prefix, possible := glob.match(pattern)
	if !possible {
		return existenceResult{value: conditionFalse}
	}
	if len(glob.matches) > 0 {
		return existenceResult{value: conditionTrue}
	}
	base := filepath.Join(s.baseDir, filepath.FromSlash(prefix))
	if snapshot, ok := s.fsys.(vfs.DirectorySnapshot); ok && !snapshot.DirectoryComplete(base) {
		return existenceResult{value: conditionUnknown, missing: []string{base}}
	}
	if glob.uncertain {
		return existenceResult{value: conditionUnknown}
	}
	return existenceResult{value: conditionFalse}
}

func (s *FileState) literalExists(target string, directory bool) existenceResult {
	info, err := s.existenceStat(target)
	if err != nil && directory {
		if directories, ok := s.fsys.(interface {
			DirInfo(string) (fs.FileInfo, bool)
		}); ok {
			if found, exists := directories.DirInfo(target); exists {
				info, err = found, nil
			}
		}
	}
	if err == nil {
		if info.IsDir() == directory {
			return existenceResult{value: conditionTrue}
		}
		return existenceResult{value: conditionFalse}
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return existenceResult{value: conditionUnknown}
	}
	if snapshot, ok := s.fsys.(vfs.DirectorySnapshot); ok && !snapshot.DirectoryComplete(filepath.Dir(target)) {
		return existenceResult{value: conditionUnknown, missing: []string{target}}
	}
	return existenceResult{value: conditionFalse}
}

// Existence tests inspect the repository entry, not a symlink's target. Keep
// parent traversal confined while allowing dangling/outward file symlinks.
func (s *FileState) existenceTarget(raw string) (string, bool) {
	clean := filepath.Clean(strings.TrimLeft(strings.TrimSpace(raw), "/"))
	if clean == "." || !filepath.IsLocal(clean) {
		return "", false
	}
	parent := filepath.Dir(clean)
	if parent != "." {
		if _, ok := s.resolveConfinedLocalPath(parent); !ok {
			return "", false
		}
	}
	return filepath.Join(s.baseDir, clean), true
}

func (s *FileState) existenceStat(target string) (fs.FileInfo, error) {
	if !vfs.IsDisk(s.fsys) || filepath.Clean(target) == filepath.Clean(s.baseDir) {
		return s.fsys.Stat(target)
	}
	for dir := filepath.Dir(target); dir != filepath.Clean(s.baseDir); dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil {
			return nil, err
		}
		if info.Mode()&fs.ModeSymlink != 0 || filepath.Dir(dir) == dir {
			return nil, fs.ErrNotExist
		}
	}
	return os.Lstat(target)
}
