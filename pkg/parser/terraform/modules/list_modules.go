package tfmodules

import (
	"sort"
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
}

// ListModuleEntries converts parsed modules to list-modules JSON rows.
func ListModuleEntries(modules map[string]ParsedModule, includeLocal bool) []ListModuleEntry {
	entries := make([]ListModuleEntry, 0, len(modules))
	for src := range modules {
		mod := modules[src]
		if mod.IsLocal && !includeLocal {
			continue
		}
		if strings.HasPrefix(mod.Source, "__") || mod.Source == "" {
			continue
		}
		entries = append(entries, ListModuleEntry{
			Name:          mod.Name,
			Source:        mod.Source,
			Version:       mod.Version,
			SourceType:    mod.SourceType,
			RegistryScope: mod.RegistryScope,
			FileName:      mod.FileName,
			DefLine:       mod.DefLine,
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
