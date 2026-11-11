package ruletest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

const (
	testDirName                  = "test"
	argumentTestDirName          = "test_arguments"
	expectedResultFileName       = "positive_expected_result.json"
	argumentsExpectedResultsName = "arguments_expected_result.json"
	emptyInputData               = "{}"
)

// LoadAPI loads the published rules that have tests from the default ruleset
// and, with credentials, the org's custom ruleset. Libraries come from the
// same API.
func LoadAPI(ctx context.Context, client datadog.Client) (*Suite, error) {
	defaultRuleset, err := client.GetDefaultRulesetWithTests(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching default rules with tests: %w", err)
	}
	customRuleset, err := client.GetCustomRulesetWithTests(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching custom rules with tests: %w", err)
	}
	libraries, err := source.NewDatadogSource(client)
	if err != nil {
		return nil, fmt.Errorf("preparing library source: %w", err)
	}

	suite := &Suite{libraries: libraries}
	for _, rule := range datadog.MergeRulesets(defaultRuleset, customRuleset).Rules {
		if !rule.IsPublished || rule.Tests == nil {
			continue
		}
		suite.Rules = append(suite.Rules, FromAPIRule(rule))
	}
	return suite, nil
}

// FromAPIRule converts a rule of the Datadog API, with its tests.
func FromAPIRule(rule *datadog.Rule) *Rule {
	out := &Rule{
		ID:       rule.ID,
		Platform: rule.Platform,
		Query:    source.ConvertRule(rule),
	}
	if rule.LegacyId != nil {
		out.LegacyID = *rule.LegacyId
	}
	if rule.Tests != nil {
		tests := &Tests{
			Files:    make([]File, len(rule.Tests.Files)),
			Expected: make([]Finding, len(rule.Tests.Expected)),
		}
		for i, f := range rule.Tests.Files {
			tests.Files[i] = File{Name: f.FileName, Content: f.Content}
		}
		for i, e := range rule.Tests.Expected {
			tests.Expected[i] = Finding{QueryName: e.ShortDescription, Severity: e.Severity, Line: e.Line, FileName: e.FileName}
		}
		out.Tests = tests
	}
	return out
}

// LoadDir loads every rule under assetsDir/queries that has tests, except
// rules of severity TRACE, with the libraries of assetsDir/libraries.
func LoadDir(ctx context.Context, assetsDir string) (*Suite, error) {
	librariesDir := filepath.Join(assetsDir, "libraries")
	if info, err := os.Stat(librariesDir); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("libraries directory %q not found", librariesDir)
	}
	suite := &Suite{libraries: dirLibraries(librariesDir)}

	err := filepath.WalkDir(filepath.Join(assetsDir, "queries"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != source.QueryFileName {
			return nil
		}
		rule, err := readRuleDir(ctx, filepath.Dir(path))
		if err != nil {
			return err
		}
		if rule != nil {
			suite.Rules = append(suite.Rules, rule)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return suite, nil
}

func readRuleDir(ctx context.Context, ruleDir string) (*Rule, error) {
	query, err := source.ReadQueryFile(ctx, ruleDir)
	if err != nil {
		return nil, err
	}
	if severity, _ := query.Metadata["severity"].(string); strings.EqualFold(severity, model.SeverityTrace) {
		return nil, nil
	}
	tests, err := readTests(filepath.Join(ruleDir, testDirName))
	if err != nil {
		return nil, fmt.Errorf("reading tests for %s: %w", ruleDir, err)
	}
	argumentTests, err := readArgumentTests(filepath.Join(ruleDir, argumentTestDirName))
	if err != nil {
		return nil, fmt.Errorf("reading argument tests for %s: %w", ruleDir, err)
	}
	if tests == nil && argumentTests == nil {
		return nil, nil
	}
	rule := &Rule{Query: query, Tests: tests, ArgumentTests: argumentTests}
	rule.ID, _ = query.Metadata["id"].(string)
	rule.LegacyID, _ = query.Metadata["legacyId"].(string)
	rule.Platform, _ = query.Metadata["platform"].(string)
	return rule, nil
}

// expectedEntry is one entry of positive_expected_result.json.
type expectedEntry struct {
	QueryName string `json:"queryName"`
	Severity  string `json:"severity"`
	Line      int    `json:"line"`
	FileName  string `json:"fileName"`
}

func (e expectedEntry) finding() Finding {
	return Finding(e)
}

type argumentCaseEntry struct {
	Arguments map[string]any  `json:"arguments"`
	Findings  []expectedEntry `json:"findings"`
}

// readFixtureDir returns the files of dir, except those named manifest, whose
// contents are passed to onManifest. It returns nil files when dir does not exist.
func readFixtureDir(dir, manifest string, onManifest func([]byte) error) ([]File, bool, error) {
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	var files []File
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		content, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return err
		}
		if d.Name() == manifest {
			return onManifest(content)
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		files = append(files, File{Name: filepath.ToSlash(rel), Content: content})
		return nil
	})
	return files, true, err
}

func readTests(dir string) (*Tests, error) {
	var expected []Finding
	files, _, err := readFixtureDir(dir, expectedResultFileName, func(content []byte) error {
		var entries []expectedEntry
		if err := json.Unmarshal(content, &entries); err != nil {
			return fmt.Errorf("%s: %w", expectedResultFileName, err)
		}
		for _, e := range entries {
			expected = append(expected, e.finding())
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(files) == 0 && len(expected) == 0 {
		return nil, nil
	}
	return &Tests{Files: files, Expected: expected}, nil
}

func readArgumentTests(dir string) (*ArgumentTests, error) {
	var cases []ArgumentCase
	manifestFound := false
	files, exists, err := readFixtureDir(dir, argumentsExpectedResultsName, func(content []byte) error {
		var entries []argumentCaseEntry
		if err := json.Unmarshal(content, &entries); err != nil {
			return fmt.Errorf("%s: %w", argumentsExpectedResultsName, err)
		}
		manifestFound = true
		for _, e := range entries {
			c := ArgumentCase{Arguments: e.Arguments, Expected: make([]Finding, 0, len(e.Findings))}
			for _, f := range e.Findings {
				c.Expected = append(c.Expected, f.finding())
			}
			cases = append(cases, c)
		}
		return nil
	})
	if err != nil || !exists {
		return nil, err
	}
	if !manifestFound {
		return nil, fmt.Errorf("%s not found", argumentsExpectedResultsName)
	}
	if len(cases) == 0 {
		return nil, fmt.Errorf("%s must contain at least one case", argumentsExpectedResultsName)
	}
	return &ArgumentTests{Files: files, Cases: cases}, nil
}

// dirLibraries serves <dir>/<platform>.rego, matched case-insensitively, with
// <dir>/<platform>.json as its input data when present.
type dirLibraries string

func (d dirLibraries) GetQueries(context.Context, *source.QueryInspectorParameters) ([]model.QueryMetadata, error) {
	return nil, nil
}

func (d dirLibraries) GetQueryLibrary(_ context.Context, platform string) (source.RegoLibraries, error) {
	dir := string(d)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return source.RegoLibraries{}, err
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.EqualFold(name, platform+".rego") {
			continue
		}
		code, err := os.ReadFile(filepath.Clean(filepath.Join(dir, name)))
		if err != nil {
			return source.RegoLibraries{}, err
		}
		lib := source.RegoLibraries{LibraryCode: string(code), LibraryInputData: emptyInputData}
		dataPath := filepath.Clean(filepath.Join(dir, strings.TrimSuffix(name, ".rego")+".json"))
		if data, err := os.ReadFile(dataPath); err == nil {
			lib.LibraryInputData = string(data)
		}
		return lib, nil
	}
	return source.RegoLibraries{}, fmt.Errorf("library %q not found in %s", platform, dir)
}
