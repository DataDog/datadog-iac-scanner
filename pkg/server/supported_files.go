/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package server

import (
	"net/http"
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
)

// fileStrategy tells the IDE how to assemble the scan unit for a file type.
type fileStrategy string

const (
	// strategyDirectory: the file may reference siblings, so the IDE should push
	// the containing directory's candidate files on the first shot.
	strategyDirectory fileStrategy = "directory"
	// strategySingleFile: the file is self-contained; push only the open file.
	strategySingleFile fileStrategy = "single_file"
	// strategyChart: the file is a Helm chart root; the IDE should push the
	// chart directory recursively (templates/, values, crds/, subcharts).
	strategyChart fileStrategy = "chart"
)

// SupportedFileEntry maps a set of file patterns to a resolution strategy. This
// is the IaC analog of the static analyzer's GET /languages.
type SupportedFileEntry struct {
	Patterns             []string     `json:"patterns"`
	Strategy             fileStrategy `json:"strategy"`
	Priority             int          `json:"priority"`
	CaseSensitive        bool         `json:"case_sensitive"`
	ExcludedSuffixes     []string     `json:"excluded_suffixes,omitempty"`
	RequiresContentCheck bool         `json:"requires_content_check"`
}

// strategyByPattern is the single source of truth for the resolution strategy of
// every supported file type. "directory" applies to Terraform (always needs
// var/local/module context), the ambiguous .yaml/.yml/.json family (whose
// platform is decided by server-side content heuristics, so the IDE
// conservatively sends the directory), .bicep, and Ansible config. "single_file"
// applies to self-contained types (Dockerfile, gRPC proto, Buildah .sh), and
// "chart" to a Helm chart root (push the chart directory recursively).
var strategyByPattern = map[string]fileStrategy{
	".tf":          strategyDirectory,
	".tofu":        strategyDirectory,
	".tf.json":     strategyDirectory,
	".tofu.json":   strategyDirectory,
	".tfvars":      strategyDirectory,
	".yaml":        strategyDirectory,
	".yml":         strategyDirectory,
	".json":        strategyDirectory,
	".bicep":       strategyDirectory,
	".cfg":         strategyDirectory,
	".conf":        strategyDirectory,
	".ini":         strategyDirectory,
	"Dockerfile":   strategySingleFile,
	"Dockerfile.*": strategySingleFile,
	".dockerfile":  strategySingleFile,
	"Chart.yaml":   strategyChart,
	".ubi8":        strategySingleFile,
	".debian":      strategySingleFile,
	".proto":       strategySingleFile,
	".sh":          strategySingleFile,
}

// supportedFiles defines the IDE matching contract. Match dot-prefixed patterns
// as suffixes and other patterns as basename globs. Choose the lowest priority,
// independently of array order. CaseSensitive comes from the routing registry:
// Dockerfile names/globs (dockerfile, DOCKERFILE, Dockerfile.<name> in any case)
// ignore case, while other extensions retain their existing case policy.
// ExcludedSuffixes always ignore case and veto that entry: registered formats
// cannot fall through to Dockerfile.*. Arbitrary variant suffixes (including
// templates, backups and archives) remain candidates and require content validation.
// Use ignore-paths to omit auxiliary files; a filename cannot identify their purpose.
// RequiresContentCheck means a filename match still needs server validation.
func supportedFiles() []SupportedFileEntry {
	rules := make(map[string]utils.FilePattern)
	for _, rule := range utils.FilePatterns() {
		rules[rule.Pattern] = rule
	}
	patterns := make([]string, 0, len(strategyByPattern))
	for p := range strategyByPattern {
		patterns = append(patterns, p)
	}
	sort.Slice(patterns, func(i, j int) bool {
		a, b := patterns[i], patterns[j]
		globA, globB := strings.ContainsAny(a, "*?["), strings.ContainsAny(b, "*?[")
		if globA != globB {
			return !globA
		}
		extA, extB := strings.HasPrefix(a, "."), strings.HasPrefix(b, ".")
		if extA != extB {
			return !extA
		}
		if extA && len(a) != len(b) {
			return len(a) > len(b)
		}
		return a < b
	})

	entries := make([]SupportedFileEntry, 0, len(patterns))
	for i, p := range patterns {
		rule, registered := rules[p]
		entry := SupportedFileEntry{
			Patterns: []string{p}, Strategy: strategyByPattern[p], Priority: i + 1,
			CaseSensitive:        !registered || rule.CaseSensitive,
			RequiresContentCheck: utils.NeedsContentCheck(rule.Token),
			ExcludedSuffixes:     rule.ExcludedSuffixes,
		}
		entries = append(entries, entry)
	}
	return entries
}

func (s *Server) handleSupportedFiles(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, supportedFiles())
}
