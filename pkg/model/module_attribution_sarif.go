/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

// ModuleAttributionSARIF is the properties.module payload emitted for instantiated findings.
// ModulePath lists the module calls from the root file down to the module holding the
// flagged resource, ModuleCodeLocation is the flagged location inside that module, and
// Source, SourceType and Version identify the repository or package holding it.
type ModuleAttributionSARIF struct {
	Source             string          `json:"source,omitempty"`
	SourceType         string          `json:"source_type,omitempty"`
	Version            string          `json:"version,omitempty"`
	DependencyType     string          `json:"dependency_type,omitempty"`
	ModuleCodeLocation SourceLocation  `json:"code_location,omitempty"`
	ModulePath         []ModulePathHop `json:"module_path"`
}

func ModuleAttributionForSARIF(attr *ModuleAttribution) *ModuleAttributionSARIF {
	if attr == nil {
		return nil
	}
	return &ModuleAttributionSARIF{
		Source:             sanitizeModuleSource(attr.Source),
		SourceType:         attr.SourceType,
		Version:            attr.Version,
		DependencyType:     attr.DependencyType,
		ModuleCodeLocation: attr.ModuleCodeLocation,
		ModulePath:         sanitizeModulePath(attr.ModulePath),
	}
}

func sanitizeModuleSource(source string) string {
	if source == "" {
		return ""
	}
	return removeURLCredentials(source)
}

func sanitizeModulePath(path []ModulePathHop) []ModulePathHop {
	if len(path) == 0 {
		return nil
	}
	out := append([]ModulePathHop(nil), path...)
	for i := range out {
		out[i].Source = sanitizeModuleSource(out[i].Source)
	}
	return out
}
