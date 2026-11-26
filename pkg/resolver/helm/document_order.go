package helm

import (
	"cmp"
	"slices"

	"gopkg.in/yaml.v3"
)

type manifestIdentity struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Namespace string `yaml:"namespace"`
		Name      string `yaml:"name"`
	} `yaml:"metadata"`
}

// orderTemplateDocuments orders named resources within each template, followed
// by documents without an identity in render order. Moving the whole split
// leaves its source index, content and markers attached to the same document.
func orderTemplateDocuments(splits []splitManifest) {
	bySource := make(map[string][]int)
	for i := range splits {
		if !splits[i].isCRD {
			bySource[splits[i].path] = append(bySource[splits[i].path], i)
		}
	}
	type identifiedSplit struct {
		identity manifestIdentity
		split    splitManifest
	}
	for _, indices := range bySource {
		if len(indices) < 2 {
			continue
		}
		documents := make([]identifiedSplit, 0, len(indices))
		for _, i := range indices {
			var identity manifestIdentity
			if err := yaml.Unmarshal(splits[i].content, &identity); err != nil ||
				identity.APIVersion == "" || identity.Kind == "" || identity.Metadata.Name == "" {
				identity = manifestIdentity{}
			}
			documents = append(documents, identifiedSplit{identity: identity, split: splits[i]})
		}
		slices.SortStableFunc(documents, func(a, b identifiedSplit) int {
			left, right := a.identity, b.identity
			if left.APIVersion == "" && right.APIVersion != "" {
				return 1
			}
			if left.APIVersion != "" && right.APIVersion == "" {
				return -1
			}
			return cmp.Or(
				cmp.Compare(left.APIVersion, right.APIVersion),
				cmp.Compare(left.Kind, right.Kind),
				cmp.Compare(left.Metadata.Namespace, right.Metadata.Namespace),
				cmp.Compare(left.Metadata.Name, right.Metadata.Name),
			)
		})
		for i, slot := range indices {
			position := splits[slot].position
			splits[slot] = documents[i].split
			splits[slot].position = position
		}
	}
}
