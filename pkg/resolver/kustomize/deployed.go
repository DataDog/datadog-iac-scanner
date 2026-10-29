package kustomize

import (
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/giturl"
	"gopkg.in/yaml.v3"
)

// Flux object kinds and API groups; constants keep the linter's duplicate
// string check quiet.
const (
	fluxKustomizationKind = "Kustomization"
	fluxGitRepoKind       = "GitRepository"
	fluxSourceGroup       = "source.toolkit.fluxcd.io"
	fluxKustomizeGroup    = "kustomize.toolkit.fluxcd.io"
)

// fluxSource is an in-scan Flux source a Kustomization can reference: its
// group, namespace and name, and the normalized spec.url of a GitRepository.
type fluxSource struct {
	group, namespace, name string
	url                    string
}

// fluxRef is a Kustomization's sourceRef: the group, namespace and name it
// selects.
type fluxRef struct{ group, namespace, name string }

// DeployedDirs returns the kustomization directories an in-repo Argo CD
// Application or Flux Kustomization deploys as-is, so the planner renders
// them as roots even when another root references them. Only candidates
// (files the analyzer marked as mentioning Argo CD or Flux) are decoded.
// A path resolves from the repo root and is kept only when the remote URL
// normalizes to the scanned repo; an empty repoURL turns the feature off.
// Sources are indexed before references are resolved, so a Kustomization
// declared before its GitRepository is found regardless of order.
// The target revision or branch is ignored; a same-name source in another
// namespace is distinguished by the namespace below.
func DeployedDirs(repo string, candidates []string, repoURL string, read func(string) ([]byte, error)) []string {
	if repoURL == "" || len(candidates) == 0 {
		return nil
	}
	scanned := giturl.Normalize(repoURL)
	var sources []fluxSource
	var kustomizations []fluxKustomization
	for _, path := range candidates {
		content, err := read(path)
		if err != nil {
			continue
		}
		for _, doc := range decodeYAMLDocs(content) {
			sources, kustomizations = indexDeployDoc(repo, scanned, doc, sources, kustomizations)
		}
	}
	deployed := map[string]bool{}
	for _, k := range kustomizations {
		paths := k.deployedPaths(sources, scanned)
		for _, p := range paths {
			deployed[p] = true
		}
	}
	out := make([]string, 0, len(deployed))
	for d := range deployed {
		out = append(out, d)
	}
	return out
}

// indexDeployDoc appends doc to sources when it is a Flux GitRepository, or
// to kustomizations when it is an Argo CD Application or Flux Kustomization.
func indexDeployDoc(repo, scanned string, doc map[string]interface{},
	sources []fluxSource, kustomizations []fluxKustomization) ([]fluxSource, []fluxKustomization) {
	kind, _ := doc["kind"].(string)
	switch kind {
	case fluxGitRepoKind:
		if s, ok := newFluxSource(doc); ok && s.group == fluxSourceGroup {
			sources = append(sources, s)
		}
	case "Application":
		if fluxGroup(doc) == "argoproj.io" {
			kustomizations = append(kustomizations, argoKustomization(repo, doc, scanned))
		}
	case fluxKustomizationKind:
		if k, ok := newFluxKustomization(repo, doc); ok {
			kustomizations = append(kustomizations, k)
		}
	}
	return sources, kustomizations
}

// fluxKustomization carries the deploy paths an Argo Application or Flux
// Kustomization holds, and the Flux sourceRef it resolves through.
type fluxKustomization struct {
	paths []string
	// ref is empty for Argo Applications, which carry their own repoURL.
	ref fluxRef
}

// newFluxKustomization reads a Flux Kustomization's spec path and sourceRef.
// Only the kustomize.toolkit.fluxcd.io group's Kustomization qualifies, and
// its sourceRef must name a GitRepository.
func newFluxKustomization(repo string, doc map[string]interface{}) (fluxKustomization, bool) {
	if fluxGroup(doc) != fluxKustomizeGroup {
		return fluxKustomization{}, false
	}
	kind, _ := doc["kind"].(string)
	if kind != "Kustomization" {
		return fluxKustomization{}, false
	}
	spec, _ := doc["spec"].(map[string]interface{})
	k := fluxKustomization{}
	// An omitted or empty spec.path deploys the source's root.
	p, _ := spec["path"].(string)
	if d, ok := repoJoin(repo, p); ok {
		k.paths = append(k.paths, d)
	}
	ref, _ := spec["sourceRef"].(map[string]interface{})
	name, _ := ref["name"].(string)
	refKind, _ := ref["kind"].(string)
	if name == "" || refKind != fluxGitRepoKind {
		return k, false
	}
	ns, _ := docPath(doc, "metadata", "namespace").(string)
	refNS, _ := ref["namespace"].(string)
	if refNS != "" {
		ns = refNS
	}
	k.ref = fluxRef{group: fluxSourceGroup, namespace: ns, name: name}
	return k, true
}

// argoKustomization reads an Argo Application's sources whose repoURL
// normalizes to the scanned repo.
func argoKustomization(repo string, doc map[string]interface{}, scanned string) fluxKustomization {
	k := fluxKustomization{}
	spec, _ := doc["spec"].(map[string]interface{})
	keep := func(source map[string]interface{}) {
		url, _ := source["repoURL"].(string)
		if giturl.Normalize(url) != scanned {
			return
		}
		if p, _ := source["path"].(string); p != "" {
			if d, ok := repoJoin(repo, p); ok {
				k.paths = append(k.paths, d)
			}
		}
	}
	// Argo CD ignores spec.source when spec.sources is set.
	if sources, ok := spec["sources"].([]interface{}); ok && len(sources) > 0 {
		for _, s := range sources {
			if source, ok := s.(map[string]interface{}); ok {
				keep(source)
			}
		}
	} else if source, ok := spec["source"].(map[string]interface{}); ok {
		keep(source)
	}
	return k
}

// deployedPaths resolves the deploy paths: a Flux Kustomization keeps its
// paths when its typed, namespace-qualified sourceRef names a GitRepository
// of the scanned repo; an Argo Application keeps paths of its own repo.
func (k fluxKustomization) deployedPaths(sources []fluxSource, scanned string) []string {
	if k.ref.name == "" {
		// An Argo Application: its paths were already filtered by repoURL.
		return k.paths
	}
	for _, s := range sources {
		if s.group != "source.toolkit.fluxcd.io" || s.name != k.ref.name || s.namespace != k.ref.namespace {
			continue
		}
		if s.url == scanned {
			return k.paths
		}
	}
	return nil
}

// newFluxSource indexes a Flux source object.
func newFluxSource(doc map[string]interface{}) (fluxSource, bool) {
	spec, _ := doc["spec"].(map[string]interface{})
	name, _ := docPath(doc, "metadata", "name").(string)
	ns, _ := docPath(doc, "metadata", "namespace").(string)
	url, _ := spec["url"].(string)
	if name == "" || url == "" {
		return fluxSource{}, false
	}
	group := fluxGroup(doc)
	return fluxSource{group: group, namespace: ns, name: name, url: giturl.Normalize(url)}, true
}

func fluxGroup(doc map[string]interface{}) string {
	av, _ := doc["apiVersion"].(string)
	group, _, _ := strings.Cut(av, "/")
	return group
}

// repoJoin resolves a spec path from the repo root, resolving symlinks as
// the planner's root directories are, and refuses a path that leaves repo.
func repoJoin(repo, path string) (string, bool) {
	p := filepath.Clean(filepath.Join(repo, filepath.FromSlash(path)))
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		p = resolved
	}
	rel, err := filepath.Rel(repo, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return p, true
}

// decodeYAMLDocs decodes every document of a multi-document YAML file.
func decodeYAMLDocs(content []byte) []map[string]interface{} {
	var out []map[string]interface{}
	dec := yaml.NewDecoder(strings.NewReader(string(content)))
	for {
		var doc map[string]interface{}
		if err := dec.Decode(&doc); err != nil {
			return out
		}
		out = append(out, doc)
	}
}

func docPath(doc map[string]interface{}, keys ...string) interface{} {
	var cur interface{} = doc
	for _, k := range keys {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil
		}
		cur = m[k]
	}
	return cur
}
