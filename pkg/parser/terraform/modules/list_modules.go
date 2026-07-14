package tfmodules

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ListModuleEntry is the JSON shape emitted by `datadog-iac-scanner list-modules`.
// Field names are stable integration contracts for hosted scan orchestration.
type ListModuleEntry struct {
	Name          string `json:"name"`
	Source        string `json:"source"`
	Version       string `json:"version,omitempty"`
	SourceType    string `json:"source_type"`
	RegistryScope string `json:"registry_scope,omitempty"`
	FileName      string `json:"file_name"`
	DefLine       int    `json:"def_line"`
	CallerPath    string `json:"caller_path,omitempty"`
	CallID        string `json:"call_id,omitempty"`
}

// ListModuleEntries converts parsed modules to list-modules JSON rows.
func ListModuleEntries(modules map[string]ParsedModule, includeLocal bool) []ListModuleEntry {
	return ListModuleEntriesRelativeTo(modules, includeLocal, "")
}

// ListModuleEntriesRelativeTo includes stable repository-relative call attribution.
func ListModuleEntriesRelativeTo(
	modules map[string]ParsedModule, includeLocal bool, repositoryRoot string,
) []ListModuleEntry {
	entries := make([]ListModuleEntry, 0, len(modules))
	for src := range modules {
		mod := modules[src]
		if mod.IsLocal && !includeLocal {
			continue
		}
		if strings.HasPrefix(mod.Source, "__") || mod.Source == "" {
			continue
		}
		callerPath := stableCallerPath(repositoryRoot, mod.FileName)
		entries = append(entries, ListModuleEntry{
			Name:          mod.Name,
			Source:        mod.Source,
			Version:       mod.Version,
			SourceType:    mod.SourceType,
			RegistryScope: mod.RegistryScope,
			FileName:      mod.FileName,
			DefLine:       mod.DefLine,
			CallerPath:    callerPath,
			CallID:        ModuleCallID(callerPath, &mod),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Source != entries[j].Source {
			return entries[i].Source < entries[j].Source
		}
		if entries[i].Name != entries[j].Name {
			return entries[i].Name < entries[j].Name
		}
		return entries[i].FileName < entries[j].FileName
	})
	return entries
}

func stableCallerPath(repositoryRoot, fileName string) string {
	cleanFile := filepath.Clean(fileName)
	if repositoryRoot != "" {
		if rel, err := filepath.Rel(filepath.Clean(repositoryRoot), cleanFile); err == nil &&
			rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(cleanFile)
}

func ModuleCallID(callerPath string, mod *ParsedModule) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		callerPath,
		strconv.Itoa(mod.DefLine),
		mod.Name,
		mod.Source,
		mod.Version,
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}
