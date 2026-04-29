package kustomize

import "regexp"

// Default generator name suffix is a 10-char hash; strip it when matching kustomization names.
var kustomizeNameHashSuffix = regexp.MustCompile(`-[a-z0-9]{10}$`)

func stripKustomizeNameHashSuffix(name string) string {
	return kustomizeNameHashSuffix.ReplaceAllString(name, "")
}

func generatorNameCandidates(resourceName string) []string {
	if resourceName == "" {
		return nil
	}
	out := []string{resourceName}
	if s := stripKustomizeNameHashSuffix(resourceName); s != resourceName && s != "" {
		out = append(out, s)
	}
	return out
}
