/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package helminstall

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"path/filepath"
	"strings"
)

// Kubernetes resources install charts too: Argo CD applications and Flux
// releases. They refer to each other and to ConfigMaps by name, in any file,
// so they are all read before any is resolved.

// manifestDoc is a Kubernetes resource of a YAML file of the scan.
type manifestDoc struct {
	path string
	doc  map[string]interface{}
}

func (m manifestDoc) name() string      { return str(mapOf(m.doc, "metadata"), "name") }
func (m manifestDoc) namespace() string { return str(mapOf(m.doc, "metadata"), "namespace") }
func (m manifestDoc) spec() map[string]interface{} {
	return mapOf(m.doc, "spec")
}

// configKey names a ConfigMap or Secret.
type configKey struct {
	kind, namespace, name string
}

// configData is the content of a ConfigMap or Secret of the scan.
type configData struct {
	data map[string]string
	// generated is set for a kustomize generator, whose resource name gets a
	// hash suffix: it is found by the name the generator gives.
	generated bool
}

func (x *Index) addConfigData(kind, namespace, name string, data map[string]string, generated bool) {
	if x.configs == nil {
		x.configs = map[configKey]configData{}
	}
	x.configs[configKey{kind, namespace, name}] = configData{data: data, generated: generated}
}

// configValue returns the key of the ConfigMap or Secret kind/name in
// namespace, or in any namespace when the scan holds only one by that name.
func (x *Index) configValue(kind, namespace, name, key string) (string, bool) {
	if c, ok := x.configs[configKey{kind, namespace, name}]; ok {
		v, found := c.data[key]
		return v, found
	}
	var match *configData
	for k, c := range x.configs {
		if k.kind == kind && k.name == name {
			if match != nil {
				return "", false
			}
			c := c
			match = &c
		}
	}
	if match == nil {
		return "", false
	}
	v, found := match.data[key]
	return v, found
}

// pendingManifests are the resources read, resolved once all files are.
type pendingManifests struct {
	argoApps, argoAppSets, fluxReleases []manifestDoc
	// fluxCharts and gitRepos are Flux sources, by namespace and name.
	fluxCharts map[configKey]manifestDoc
	gitRepos   map[configKey]string
	// readDirs are the directories whose YAML files were searched for the
	// ConfigMaps of a release.
	readDirs map[string]bool
}

func (d *discovery) manifests(path string) {
	data := d.read(path)
	if data == nil || !SniffDescriptor(data) && !holdsConfig(data) {
		return
	}
	d.readManifests(path, data)
}

// Kinds of the resources discovery reads, and their API groups.
const (
	argoGroup         = "argoproj.io"
	fluxHelmGroup     = "helm.toolkit.fluxcd.io"
	fluxSourceGroup   = "source.toolkit.fluxcd.io"
	coreGroup         = "v1"
	kindApplication   = "Application"
	kindAppSet        = "ApplicationSet"
	kindHelmRelease   = "HelmRelease"
	kindHelmChart     = "HelmChart"
	kindGitRepository = "GitRepository"
	kindConfigMap     = "ConfigMap"
	kindSecret        = "Secret"
)

func (d *discovery) readManifests(path string, data []byte) {
	p := &d.pending
	if p.fluxCharts == nil {
		p.fluxCharts = map[configKey]manifestDoc{}
		p.gitRepos = map[configKey]string{}
	}
	for _, doc := range yamlDocuments(data) {
		m := manifestDoc{path: path, doc: doc}
		group, _, _ := strings.Cut(str(doc, "apiVersion"), "/")
		kind := str(doc, "kind")
		switch group + "/" + kind {
		case argoGroup + "/" + kindApplication:
			p.argoApps = append(p.argoApps, m)
		case argoGroup + "/" + kindAppSet:
			p.argoAppSets = append(p.argoAppSets, m)
		case fluxHelmGroup + "/" + kindHelmRelease:
			p.fluxReleases = append(p.fluxReleases, m)
		case fluxSourceGroup + "/" + kindHelmChart:
			p.fluxCharts[configKey{kind, m.namespace(), m.name()}] = m
		case fluxSourceGroup + "/" + kindGitRepository:
			p.gitRepos[configKey{kind, m.namespace(), m.name()}] = str(m.spec(), "url")
		case coreGroup + "/" + kindConfigMap, coreGroup + "/" + kindSecret:
			d.recordConfigResource(kind, m)
		}
	}
}

// holdsConfig reports whether a YAML file may hold a ConfigMap or a Secret.
func holdsConfig(data []byte) bool {
	return bytes.Contains(data, []byte("kind: "+kindConfigMap)) || bytes.Contains(data, []byte("kind: "+kindSecret))
}

// recordConfigResource records the data of a ConfigMap or Secret manifest.
func (d *discovery) recordConfigResource(kind string, m manifestDoc) {
	if _, encrypted := m.doc["sops"]; encrypted {
		return
	}
	data := map[string]string{}
	for k, v := range mapOf(m.doc, "data") {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if kind == kindSecret {
			decoded, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				continue
			}
			s = string(decoded)
		}
		data[k] = s
	}
	for k, v := range mapOf(m.doc, "stringData") {
		if s, ok := v.(string); ok {
			data[k] = s
		}
	}
	d.idx.addConfigData(kind, m.namespace(), m.name(), data, false)
}

// readConfigDir reads the ConfigMaps and Secrets of the YAML files of dir,
// where a release keeps those it takes values from.
func (d *discovery) readConfigDir(dir string) {
	if d.pending.readDirs == nil {
		d.pending.readDirs = map[string]bool{}
	}
	if d.pending.readDirs[dir] {
		return
	}
	d.pending.readDirs[dir] = true
	for _, e := range readDir(d.fsys(), dir) {
		if e.IsDir() || !isYAMLFile(e.Name()) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data := d.read(path)
		if data == nil || !holdsConfig(data) {
			continue
		}
		for _, doc := range yamlDocuments(data) {
			if kind := str(doc, "kind"); str(doc, "apiVersion") == coreGroup && (kind == kindConfigMap || kind == kindSecret) {
				d.recordConfigResource(kind, manifestDoc{path: path, doc: doc})
			}
		}
	}
}

func (d *discovery) resolveManifests() {
	for _, r := range d.pending.fluxReleases {
		d.readConfigDir(filepath.Dir(r.path))
	}
	for _, app := range d.pending.argoApps {
		d.argoApplication(app.path, app.doc, "")
	}
	for _, set := range d.pending.argoAppSets {
		d.argoApplicationSet(set)
	}
	for _, r := range d.pending.fluxReleases {
		d.fluxRelease(r)
	}
}

// sameRepository reports whether a descriptor's repository URL is the scanned
// repository's, or may be when either is unknown.
func (d *discovery) sameRepository(repoURL string) bool {
	if repoURL == "" || d.repoURL == "" {
		return true
	}
	return normalizeRepoURL(repoURL) == normalizeRepoURL(d.repoURL)
}

// normalizeRepoURL reduces a git URL to host/path, whatever its scheme.
func normalizeRepoURL(raw string) string {
	s := strings.TrimSpace(raw)
	if strings.HasPrefix(s, "git@") {
		// git@host:org/repo
		s = "ssh://" + strings.Replace(strings.TrimPrefix(s, "git@"), ":", "/", 1)
	}
	host, p := s, ""
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		host, p = u.Host, u.Path
	} else if i := strings.Index(s, "/"); i >= 0 {
		host, p = s[:i], s[i:]
	}
	p = strings.TrimSuffix(strings.Trim(p, "/"), ".git")
	return strings.ToLower(host) + "/" + strings.ToLower(p)
}

// repoPath resolves a path relative to the root of the repository.
func (d *discovery) repoPath(p string) string {
	return filepath.Join(d.idx.root, filepath.FromSlash(strings.TrimPrefix(p, "/")))
}
