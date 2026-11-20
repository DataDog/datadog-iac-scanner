/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package rulefixture prepares explicitly owned rule-test inputs independently
// of the policy runner that consumes them.
package rulefixture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

// Suite owns a validated manifest and its immutable fixture contents.
type Suite struct {
	cases []datadog.RuleTestCase
	files map[string][]byte
}

// Input is one independently prepared case. Filesystem contains only its owned
// assets; Targets is the exact supplied document/source-metadata set.
type Input struct {
	Name       string
	Domain     datadog.RuleTestInput
	Root       string
	Targets    []string
	Filesystem vfs.FS
	Expected   []datadog.TestFinding
}

// Load opts into the explicit domain only when its reserved
// manifest is present. Existing backend payloads retain their original path.
func Load(tests *datadog.RuleTests) (*Suite, error) {
	if tests == nil {
		return nil, nil
	}
	var manifest *datadog.TestFile
	for i := range tests.Files {
		if tests.Files[i].FileName != datadog.RuleTestCasesFile {
			continue
		}
		if manifest != nil {
			return nil, fmt.Errorf("duplicate rule test case manifest")
		}
		manifest = &tests.Files[i]
	}
	if manifest == nil {
		return nil, nil
	}
	var definition datadog.RuleTestCases
	decoder := json.NewDecoder(bytes.NewReader(manifest.Content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&definition); err != nil {
		return nil, fmt.Errorf("decoding rule test cases: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("rule test case manifest must contain exactly one JSON value")
	}
	if definition.Version != 1 || len(definition.Cases) == 0 {
		return nil, fmt.Errorf("rule test cases require version 1 and at least one case")
	}
	files, err := fixtureAssets(tests.Files)
	if err != nil {
		return nil, err
	}
	prepared := &Suite{cases: definition.Cases, files: files}
	names := make(map[string]bool, len(definition.Cases))
	for i := range definition.Cases {
		test := &definition.Cases[i]
		if test.Name == "" || names[test.Name] {
			return nil, fmt.Errorf("rule test case names must be nonempty and unique: %q", test.Name)
		}
		names[test.Name] = true
		if err := prepared.validate(test); err != nil {
			return nil, fmt.Errorf("case %q: %w", test.Name, err)
		}
	}
	return prepared, nil
}

func fixtureAssets(entries []datadog.TestFile) (map[string][]byte, error) {
	files := make(map[string][]byte, len(entries)-1)
	for _, file := range entries {
		if file.FileName == datadog.RuleTestCasesFile {
			continue
		}
		if !validFixturePath(file.FileName, false) {
			return nil, fmt.Errorf("invalid fixture asset path %q", file.FileName)
		}
		if _, exists := files[file.FileName]; exists {
			return nil, fmt.Errorf("duplicate fixture asset %q", file.FileName)
		}
		files[file.FileName] = bytes.Clone(file.Content)
	}
	return files, nil
}

// Paths use the portable slash-separated wire format. Reject aliases before
// joining a filesystem root so ownership cannot depend on host normalization.
func validFixturePath(name string, root bool) bool {
	return name != "" && (root || name != ".") && name != ".." &&
		!strings.HasPrefix(name, "../") && !strings.HasPrefix(name, "/") &&
		!strings.ContainsAny(name, "\\:\x00") && path.Clean(name) == name
}

func (p *Suite) validate(test *datadog.RuleTestCase) error {
	switch test.Input {
	case datadog.RuleTestDocuments:
		if test.Root != "" {
			return fmt.Errorf("document input cannot declare a configuration root")
		}
	case datadog.RuleTestConfiguration:
		if !validFixturePath(test.Root, true) {
			return fmt.Errorf("configuration input requires an owned relative root")
		}
	default:
		return fmt.Errorf("unknown input domain %q", test.Input)
	}
	if len(test.Targets) == 0 {
		return fmt.Errorf("at least one target is required")
	}
	owned := make(map[string]bool, len(test.Assets))
	for _, asset := range test.Assets {
		if _, exists := p.files[asset]; !exists {
			return fmt.Errorf("asset %q is not in the fixture bundle", asset)
		}
		if owned[asset] {
			return fmt.Errorf("duplicate owned asset %q", asset)
		}
		owned[asset] = true
	}
	targets := make(map[string]bool, len(test.Targets))
	for _, target := range test.Targets {
		if !owned[target] {
			return fmt.Errorf("target %q is not an owned asset", target)
		}
		if targets[target] {
			return fmt.Errorf("duplicate target %q", target)
		}
		targets[target] = true
		if test.Input == datadog.RuleTestConfiguration && test.Root != "." && !strings.HasPrefix(target, test.Root+"/") {
			return fmt.Errorf("target %q is outside configuration root %q", target, test.Root)
		}
	}
	return validateExpectedPaths(test, targets)
}

func validateExpectedPaths(test *datadog.RuleTestCase, targets map[string]bool) error {
	for _, expected := range test.Expected {
		if expected.FileName == "" {
			continue
		}
		if !validFixturePath(expected.FileName, false) {
			return fmt.Errorf("invalid expected finding path %q", expected.FileName)
		}
		target := expected.FileName
		if test.Input == datadog.RuleTestConfiguration && test.Root != "." {
			target = path.Join(test.Root, target)
		}
		if !targets[target] {
			return fmt.Errorf("expected finding path %q is not a case target", expected.FileName)
		}
	}
	return nil
}

// Len reports the number of explicitly declared cases.
func (s *Suite) Len() int { return len(s.cases) }

// Prepare binds a case to a caller-owned path namespace without reading or
// writing the host filesystem. Each call creates an independent read-only view.
func (s *Suite) Prepare(index int, namespaceRoot string) (Input, error) {
	if index < 0 || index >= len(s.cases) {
		return Input{}, fmt.Errorf("rule test case index %d is out of range", index)
	}
	if !filepath.IsAbs(namespaceRoot) || filepath.Clean(namespaceRoot) != namespaceRoot {
		return Input{}, fmt.Errorf("fixture namespace must be a clean absolute path")
	}
	test := &s.cases[index]
	assets := make(map[string][]byte, len(test.Assets))
	for _, asset := range test.Assets {
		assets[filepath.Join(namespaceRoot, filepath.FromSlash(asset))] = s.files[asset]
	}
	targets := make([]string, len(test.Targets))
	for i, target := range test.Targets {
		targets[i] = filepath.Join(namespaceRoot, filepath.FromSlash(target))
	}
	root := namespaceRoot
	if test.Input == datadog.RuleTestConfiguration {
		root = filepath.Join(root, filepath.FromSlash(test.Root))
	}
	return Input{
		Name: test.Name, Domain: test.Input, Root: root, Targets: targets,
		Filesystem: vfs.NewMemFS(assets), Expected: append([]datadog.TestFinding(nil), test.Expected...),
	}, nil
}

// FindingPath preserves a finding's source identity within one prepared case.
// A basename cannot stand in for another target in a different directory.
func FindingPath(root string, targets []string, filename string) (string, error) {
	candidate := filepath.FromSlash(filename)
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(root, candidate)
	}
	candidate = filepath.Clean(candidate)
	relative, err := filepath.Rel(root, candidate)
	if err != nil || !validFixturePath(filepath.ToSlash(relative), false) {
		return "", fmt.Errorf("finding source %q is outside its case root", filename)
	}
	for _, target := range targets {
		if filepath.Clean(target) == candidate {
			return filepath.ToSlash(relative), nil
		}
	}
	return "", fmt.Errorf("finding source %q is not a case target", filename)
}
