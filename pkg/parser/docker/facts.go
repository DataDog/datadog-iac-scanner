package docker

import (
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/shell"
	"github.com/distribution/reference"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	buildkitshell "github.com/moby/buildkit/frontend/dockerfile/shell"
)

const (
	unknownFact  = "unknown"
	scratchImage = "scratch"
	remoteSource = "remote"
)

type Image struct {
	Default          *Image      `json:"default,omitempty"`
	VersionKnown     bool        `json:"version_known"`
	VersionSpecified bool        `json:"version_specified"`
	Reference        shell.Value `json:"reference"`
	Kind             string      `json:"kind"`
	Registry         string      `json:"registry"`
	Repository       string      `json:"repository"`
	Tag              string      `json:"tag"`
	Digest           string      `json:"digest"`
	Stage            int         `json:"stage"`
}

type Binding struct {
	Name       string      `json:"name"`
	Value      shell.Value `json:"value"`
	HasDefault bool        `json:"has_default"`
}

type BindingScope struct {
	Parent   int       `json:"parent"`
	Kind     string    `json:"kind"`
	Bindings []Binding `json:"bindings"`
}

type Context struct {
	Deferred    bool        `json:"deferred,omitempty"`
	Environment int         `json:"environment"`
	Arguments   int         `json:"arguments"`
	User        shell.Value `json:"user"`
	Workdir     shell.Value `json:"workdir"`
}

type FileSource struct {
	Content string      `json:"content,omitempty"`
	Expand  bool        `json:"expand,omitempty"`
	Value   shell.Value `json:"value"`
	Kind    string      `json:"kind"`
	Name    string      `json:"name"`
}

type Flag struct {
	Name  string      `json:"name"`
	Value shell.Value `json:"value"`
}

type Healthcheck struct {
	Disabled      bool   `json:"disabled"`
	Interval      string `json:"interval,omitempty"`
	Timeout       string `json:"timeout,omitempty"`
	StartPeriod   string `json:"start_period,omitempty"`
	StartInterval string `json:"start_interval,omitempty"`
	Retries       int    `json:"retries,omitempty"`
}

type Copy struct {
	SourceStage int          `json:"source_stage"`
	Sources     []FileSource `json:"sources"`
	Destination shell.Value  `json:"destination"`
	From        *shell.Value `json:"from,omitempty"`
	Owner       *shell.Value `json:"owner,omitempty"`
	Mode        *shell.Value `json:"mode,omitempty"`
	Checksum    *shell.Value `json:"checksum,omitempty"`
	Link        bool         `json:"link"`
	Exclude     []string     `json:"exclude,omitempty"`
}

type Mount struct {
	Kind     string       `json:"kind"`
	Target   shell.Value  `json:"target"`
	Source   shell.Value  `json:"source"`
	From     *shell.Value `json:"from,omitempty"`
	ReadOnly bool         `json:"read_only"`
	CacheID  shell.Value  `json:"cache_id"`
	Sharing  string       `json:"sharing"`
	Required bool         `json:"required"`
}

func value(raw string) shell.Value {
	result := shell.Value{Text: raw, Known: true}
	if !strings.ContainsAny(raw, "$\"'\\") {
		return result
	}
	lexer := buildkitshell.NewLex('\\')
	lexer.SkipUnsetEnv = true
	expanded, err := lexer.ProcessWordWithMatches(raw, emptyEnvironment{})
	if err != nil {
		return shell.Value{Raw: raw}
	}
	result.Text = expanded.Result
	result.Known = len(expanded.Unmatched) == 0
	if !result.Known || result.Text != raw {
		result.Raw = raw
	}
	for name := range expanded.Unmatched {
		result.References = append(result.References, name)
	}
	sort.Strings(result.References)
	return result
}

func image(raw string, stages []Stage) *Image {
	result := &Image{Reference: value(raw), Kind: unknownFact, Stage: -1}
	if !result.Reference.Known {
		tail := raw[strings.LastIndex(raw, "/")+1:]
		result.VersionKnown = value(tail).Known
		lexer := buildkitshell.NewLex('\\')
		skeleton, _, err := lexer.ProcessWord(raw, placeholderEnvironment{})
		if err == nil {
			tail = skeleton[strings.LastIndex(skeleton, "/")+1:]
			if strings.ContainsAny(tail, ":@") {
				result.VersionKnown = true
				result.VersionSpecified = true
			}
		}
		return result
	}
	for i := len(stages) - 1; i >= 0; i-- {
		if stages[i].Name != "" && strings.EqualFold(stages[i].Name, raw) {
			result.Kind = "stage"
			result.Stage = i
			return result
		}
	}
	if raw == scratchImage {
		result.Kind = scratchImage
		return result
	}
	named, err := reference.ParseNormalizedNamed(raw)
	if err != nil {
		return result
	}
	result.Kind = "image"
	result.VersionKnown = true
	result.Registry = reference.Domain(named)
	result.Repository = reference.Path(named)
	if tagged, ok := named.(reference.Tagged); ok {
		result.Tag = tagged.Tag()
	}
	if digested, ok := named.(reference.Digested); ok {
		result.Digest = digested.Digest().String()
	}
	result.VersionSpecified = result.Tag != "" || result.Digest != ""
	return result
}

func copyFacts(command any) *Copy {
	result := &Copy{Sources: []FileSource{}, Exclude: []string{}, SourceStage: -1}
	var sources instructions.SourcesAndDest
	switch typed := command.(type) {
	case *instructions.AddCommand:
		sources = typed.SourcesAndDest
		result.Owner, result.Mode, result.Checksum = optionalValue(typed.Chown), optionalValue(typed.Chmod), optionalValue(typed.Checksum)
		result.Link, result.Exclude = typed.Link, typed.ExcludePatterns
	case *instructions.CopyCommand:
		sources = typed.SourcesAndDest
		result.From, result.Owner, result.Mode = optionalValue(typed.From), optionalValue(typed.Chown), optionalValue(typed.Chmod)
		result.Link, result.Exclude = typed.Link, typed.ExcludePatterns
	}
	result.Destination = value(sources.DestPath)
	for _, source := range sources.SourcePaths {
		fact := FileSource{Value: value(source), Kind: "local"}
		if !fact.Value.Known {
			fact.Kind = unknownFact
		} else if isRemoteSource(source) {
			fact.Kind = remoteSource
		} else if strings.HasPrefix(source, "git@") {
			fact.Kind = remoteSource
		}
		fact.Name = path.Base(source)
		result.Sources = append(result.Sources, fact)
	}
	for _, source := range sources.SourceContents {
		result.Sources = append(result.Sources, FileSource{Kind: "inline", Name: source.Path, Content: source.Data, Expand: source.Expand})
	}
	return result
}

func isRemoteSource(source string) bool {
	parsed, err := url.Parse(source)
	if err != nil {
		return false
	}
	switch parsed.Scheme {
	case "http", "https", "git", "ssh":
		return true
	}
	return false
}

func optionalValue(raw string) *shell.Value {
	if raw == "" {
		return nil
	}
	result := value(raw)
	return &result
}

type emptyEnvironment struct{}

func (emptyEnvironment) Get(string) (string, bool) { return "", false }
func (emptyEnvironment) Keys() []string            { return nil }

type placeholderEnvironment struct{}

func (placeholderEnvironment) Get(string) (string, bool) { return "dynamic", true }
func (placeholderEnvironment) Keys() []string            { return nil }
