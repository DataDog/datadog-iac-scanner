package helm

import (
	"bytes"
	"cmp"
	"encoding/json"
	"slices"

	"github.com/DataDog/datadog-iac-scanner/pkg/helmmarker"
	"gopkg.in/yaml.v3"
)

type manifestIdentity struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Namespace    string `yaml:"namespace"`
		Name         string `yaml:"name"`
		GenerateName string `yaml:"generateName"`
	} `yaml:"metadata"`
}

func (id *manifestIdentity) rank() int {
	switch {
	case id.Metadata.Name != "":
		return 0
	case id.Metadata.GenerateName != "":
		return 1
	default:
		return 2
	}
}

type identifiedSplit struct {
	identity manifestIdentity
	split    splitManifest
	content  []byte
}

// orderTemplateDocuments orders each template's named resources, generated
// names and unidentified documents. Ties are ordered by canonical content.
// Moving the whole split keeps source coordinates attached to the document.
func orderTemplateDocuments(splits []splitManifest) {
	bySource := make(map[string][]int)
	for i := range splits {
		if !splits[i].isCRD {
			bySource[splits[i].path] = append(bySource[splits[i].path], i)
		}
	}
	for _, indices := range bySource {
		if len(indices) < 2 {
			continue
		}
		documents := make([]identifiedSplit, 0, len(indices))
		for _, i := range indices {
			var identity manifestIdentity
			if err := yaml.Unmarshal(splits[i].content, &identity); err != nil ||
				identity.APIVersion == "" || identity.Kind == "" || identity.rank() == 2 {
				identity = manifestIdentity{}
			}
			if identity.Metadata.Name != "" {
				identity.Metadata.GenerateName = ""
			}
			documents = append(documents, identifiedSplit{identity: identity, split: splits[i]})
		}
		slices.SortStableFunc(documents, func(a, b identifiedSplit) int {
			left, right := a.identity, b.identity
			return cmp.Or(
				cmp.Compare(left.rank(), right.rank()),
				cmp.Compare(left.APIVersion, right.APIVersion),
				cmp.Compare(left.Kind, right.Kind),
				cmp.Compare(left.Metadata.Namespace, right.Metadata.Namespace),
				cmp.Compare(left.Metadata.Name, right.Metadata.Name),
				cmp.Compare(left.Metadata.GenerateName, right.Metadata.GenerateName),
			)
		})
		sortManifestTies(documents)
		for i, slot := range indices {
			position := splits[slot].position
			splits[slot] = documents[i].split
			splits[slot].position = position
		}
	}
}

func sortManifestTies(documents []identifiedSplit) {
	for start := 0; start < len(documents); {
		end := start + 1
		for end < len(documents) && documents[end].identity == documents[start].identity {
			end++
		}
		if end-start > 1 {
			tied := documents[start:end]
			for i := range tied {
				tied[i].content = canonicalManifestContent(tied[i].split.content)
			}
			slices.SortStableFunc(tied, func(a, b identifiedSplit) int {
				return bytes.Compare(a.content, b.content)
			})
		}
		start = end
	}
}

func canonicalManifestContent(content []byte) []byte {
	// Decoding into values drops YAML comments, including the scanner stamps.
	// JSON gives Kubernetes mappings a stable key order.
	var value any
	if err := yaml.Unmarshal(content, &value); err == nil {
		if canonical, err := json.Marshal(value); err == nil {
			return canonical
		}
	}
	// Malformed or non-JSON YAML still gets a deterministic content key.
	return helmmarker.RemoveIDLines(content)
}
