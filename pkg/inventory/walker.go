/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import (
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// platformWalker converts a single parsed document into inventory resources.
// handled=false lets the next walker try — necessary for the shared YAML/JSON
// kinds where multiple platforms compete for the same file.
type platformWalker interface {
	// Platform returns the lowercase canonical name (e.g. "terraform"),
	// matched case-insensitively against the enabled platforms set.
	Platform() string
	Kinds() []model.FileKind
	Walk(filePath string, doc model.Document) (resources []Resource, handled bool)
}

// registry order matters for shared YAML/JSON kinds: more specific detections
// before more permissive ones (Ansible last — task shape is most permissive).
var registry = []platformWalker{
	terraformWalker{},
	dockerfileWalker{},
	cloudFormationWalker{},
	kubernetesWalker{},
	ciCDWalker{},
	ansibleWalker{},
}

// WalkFiles enumerates IaC resources across all parsed files. Only platforms
// present in enabledPlatforms are walked; nil or empty enables all platforms.
// When opts is set, Terraform module provenance is attached to module blocks and
// to resources declared inside resolved or local module bodies.
func WalkFiles(files model.FileMetadatas, enabledPlatforms []string, opts *WalkOptions) []Resource {
	enabled := newPlatformSet(enabledPlatforms)
	var resources []Resource
	// A YAML file can produce multiple FileMetadata entries (parsed by both the
	// default and CI/CD parsers), so resources are deduplicated by stable key.
	seen := make(map[string]struct{})
	for _, f := range files {
		if f == nil {
			continue
		}
		// LineInfoDocument retains _dd_ line annotations stripped from Document.
		doc := model.Document(f.LineInfoDocument)
		if len(doc) == 0 {
			doc = f.Document
		}
		if len(doc) == 0 {
			continue
		}
		for _, w := range registry {
			if !enabled.has(w.Platform()) || !kindMatches(w.Kinds(), f.Kind) {
				continue
			}
			rs, handled := w.Walk(f.FilePath, doc)
			if !handled {
				continue
			}
			for i := range rs {
				key := resourceKey(&rs[i])
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				resources = append(resources, rs[i])
			}
			break
		}
	}
	idx := newModuleIndex(opts, files)
	enrichTerraformModules(resources, idx)
	return resources
}

func resourceKey(r *Resource) string {
	return strings.Join([]string{
		r.Platform,
		r.File,
		resourceAddress(r),
		strconv.Itoa(r.StartLine),
		strconv.Itoa(r.EndLine),
	}, "\x00")
}

func kindMatches(kinds []model.FileKind, kind model.FileKind) bool {
	for _, k := range kinds {
		if k == kind {
			return true
		}
	}
	return false
}

type platformSet struct {
	all     bool
	members map[string]struct{}
}

func newPlatformSet(platforms []string) platformSet {
	if len(platforms) == 0 {
		return platformSet{all: true}
	}
	members := make(map[string]struct{}, len(platforms))
	for _, p := range platforms {
		if p == "" {
			// A single empty string in the list means "all platforms"; any
			// valid names seen so far are discarded.
			return platformSet{all: true}
		}
		members[strings.ToLower(p)] = struct{}{}
	}
	return platformSet{members: members}
}

func (s platformSet) has(platform string) bool {
	if s.all {
		return true
	}
	_, ok := s.members[strings.ToLower(platform)]
	return ok
}
