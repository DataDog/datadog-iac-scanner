/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package eval

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/DataDog/datadog-iac-scanner/pkg/pulumi/capture"
	"gopkg.in/yaml.v3"
)

// Runtimes the scanner evaluates.
const (
	RuntimePython = "python"
	RuntimeGo     = "go"
)

// Project is a Pulumi project: a directory with a Pulumi.yaml.
type Project struct {
	// Dir is the absolute project directory.
	Dir     string
	Name    string
	Runtime string
	// Options are the runtime options (runtime.options in Pulumi.yaml).
	Options map[string]any
	// Main is the program path relative to Dir ("" for Dir itself).
	Main string
	// StackConfigDir is where the Pulumi.<stack>.yaml files are, relative to Dir.
	StackConfigDir string
	// Config is the project-level configuration block.
	Config map[string]any
}

// Stack is one stack of a project.
type Stack struct {
	Name string
	// File is the absolute path of Pulumi.<stack>.yaml, "" for the synthetic stack.
	File   string
	Config map[string]any
}

type projectFile struct {
	Name           string         `yaml:"name"`
	Runtime        yaml.Node      `yaml:"runtime"`
	Main           string         `yaml:"main"`
	StackConfigDir string         `yaml:"stackConfigDir"`
	Config         map[string]any `yaml:"config"`
}

type stackFile struct {
	Config map[string]any `yaml:"config"`
}

// ProjectFiles are the names of a Pulumi project file, in lookup order.
var ProjectFiles = []string{"Pulumi.yaml", "Pulumi.yml"}

var stackFileName = regexp.MustCompile(`^Pulumi\.(.+)\.ya?ml$`)

// LoadProject reads the Pulumi.yaml (or Pulumi.yml) of dir.
func LoadProject(dir string) (*Project, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	var data []byte
	for _, name := range ProjectFiles {
		data, err = os.ReadFile(filepath.Join(abs, name)) //nolint:gosec // the project file of the directory to evaluate
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("no Pulumi.yaml in %s: %w", abs, err)
	}
	var f projectFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("invalid Pulumi.yaml in %s: %w", abs, err)
	}
	p := &Project{Dir: abs, Name: f.Name, Main: f.Main, StackConfigDir: f.StackConfigDir, Config: normalizeMap(f.Config)}
	switch f.Runtime.Kind {
	case yaml.ScalarNode:
		p.Runtime = f.Runtime.Value
	case yaml.MappingNode:
		var r struct {
			Name    string         `yaml:"name"`
			Options map[string]any `yaml:"options"`
		}
		if err := f.Runtime.Decode(&r); err != nil {
			return nil, fmt.Errorf("invalid runtime in %s: %w", abs, err)
		}
		p.Runtime, p.Options = r.Name, normalizeMap(r.Options)
	}
	if p.Name == "" || p.Runtime == "" {
		return nil, fmt.Errorf("pulumi.yaml in %s has no name or no runtime", abs)
	}
	return p, nil
}

// Stacks returns the committed stacks (one per Pulumi.<stack>.yaml), or the
// synthetic stack "dd-scan" when there is none (D18).
func (p *Project) Stacks() ([]Stack, error) {
	dir := filepath.Join(p.Dir, p.StackConfigDir)
	entries, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	var stacks []Stack
	for _, e := range entries {
		m := stackFileName.FindStringSubmatch(e.Name())
		if m == nil || e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path) //nolint:gosec // a stack file of the project
		if err != nil {
			return nil, err
		}
		var f stackFile
		if err := yaml.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("invalid stack file %s: %w", path, err)
		}
		stacks = append(stacks, Stack{Name: m[1], File: path, Config: normalizeMap(f.Config)})
	}
	sort.Slice(stacks, func(i, j int) bool { return stacks[i].Name < stacks[j].Name })
	if len(stacks) == 0 {
		stacks = []Stack{{Name: capture.SyntheticStack}}
	}
	return stacks, nil
}

// programDir is the directory the program runs in, as the Pulumi CLI chooses
// it: main when it is a directory, the directory of main when it is a file,
// the project directory without main, or when main cannot be read, so that
// the program reports the missing main itself.
func (p *Project) programDir() string {
	if p.Main == "" {
		return p.Dir
	}
	main := filepath.Join(p.Dir, p.Main)
	info, err := os.Stat(main)
	switch {
	case err != nil:
		return p.Dir
	case info.IsDir():
		return main
	default:
		return filepath.Dir(main)
	}
}

func (p *Project) option(name string) string {
	if v, ok := p.Options[name].(string); ok {
		return v
	}
	return ""
}

// normalizeMap converts the maps decoded by yaml.v3 so that they can be
// encoded as JSON (yaml.v3 yields map[any]any for non-string keys).
func normalizeMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = normalize(v)
	}
	return out
}

func normalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return normalizeMap(t)
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[fmt.Sprint(k)] = normalize(e)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = normalize(e)
		}
		return out
	}
	return v
}
