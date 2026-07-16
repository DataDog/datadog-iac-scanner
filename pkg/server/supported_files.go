/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package server

import (
	"net/http"
	"sort"
)

// fileStrategy tells the IDE how to assemble the scan unit for a file type.
type fileStrategy string

const (
	// strategyDirectory: the file may reference siblings, so the IDE should push
	// the containing directory's candidate files on the first shot.
	strategyDirectory fileStrategy = "directory"
	// strategySingleFile: the file is self-contained; push only the open file.
	strategySingleFile fileStrategy = "single_file"
)

// SupportedFileEntry maps a set of file patterns to a resolution strategy. This
// is the IaC analog of the static analyzer's GET /languages.
type SupportedFileEntry struct {
	Patterns []string     `json:"patterns"`
	Strategy fileStrategy `json:"strategy"`
}

// strategyByPattern is the single source of truth for the resolution strategy of
// every supported file type. "directory" applies to Terraform (always needs
// var/local/module context), the ambiguous .yaml/.yml/.json family (whose
// platform is decided by server-side content heuristics, so the IDE
// conservatively sends the directory), .bicep, and Ansible config. "single_file"
// applies to self-contained types (Dockerfile, gRPC proto, Buildah .sh).
//
// Keys are the IDE-facing patterns (dotted extensions, or full filenames like
// "Dockerfile"). TestSupportedFiles_NoDrift asserts this covers every
// analyzer.PossibleFileTypes() entry so a newly supported type can't be missed.
var strategyByPattern = map[string]fileStrategy{
	".tf":         strategyDirectory,
	".tfvars":     strategyDirectory,
	".yaml":       strategyDirectory,
	".yml":        strategyDirectory,
	".json":       strategyDirectory,
	".bicep":      strategyDirectory,
	".cfg":        strategyDirectory,
	".conf":       strategyDirectory,
	".conflist":   strategySingleFile,
	".ini":        strategyDirectory,
	"Dockerfile":  strategySingleFile,
	".dockerfile": strategySingleFile,
	".ubi8":       strategySingleFile,
	".debian":     strategySingleFile,
	".proto":      strategySingleFile,
	".sh":         strategySingleFile,
}

// supportedFiles builds the supported-files response: one entry per pattern,
// sorted for deterministic output.
func supportedFiles() []SupportedFileEntry {
	patterns := make([]string, 0, len(strategyByPattern))
	for p := range strategyByPattern {
		patterns = append(patterns, p)
	}
	sort.Strings(patterns)

	entries := make([]SupportedFileEntry, 0, len(patterns))
	for _, p := range patterns {
		entries = append(entries, SupportedFileEntry{Patterns: []string{p}, Strategy: strategyByPattern[p]})
	}
	return entries
}

func (s *Server) handleSupportedFiles(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, supportedFiles())
}
