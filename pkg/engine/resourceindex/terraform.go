/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resourceindex

import (
	"path/filepath"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

var terraformKubernetesWorkloadTypes = map[string]struct{}{
	"kubernetes_pod":                       {},
	"kubernetes_pod_v1":                    {},
	"kubernetes_deployment":                {},
	"kubernetes_deployment_v1":             {},
	"kubernetes_daemonset":                 {},
	"kubernetes_daemon_set_v1":             {},
	"kubernetes_stateful_set":              {},
	"kubernetes_stateful_set_v1":           {},
	"kubernetes_replication_controller":    {},
	"kubernetes_replication_controller_v1": {},
	"kubernetes_job":                       {},
	"kubernetes_job_v1":                    {},
	"kubernetes_cron_job":                  {},
	"kubernetes_cron_job_v1":               {},
}

func indexTerraformDoc(index, doc map[string]interface{}, docID string, fm *model.FileMetadata) {
	indexTerraformResources(index, doc, docID, fm)
	indexTerraformData(index, doc, docID, fm)
	indexTerraformModules(index, doc, docID, fm)
	indexTerraformVariables(index, doc, docID, fm)
	indexTerraformOutputs(index, doc, docID, fm)
	indexTerraformProvidersBlock(index, doc, docID, fm)
}

func indexTerraformResources(index, doc map[string]interface{}, docID string, fm *model.FileMetadata) {
	if resources, ok := asMap(doc["resource"]); !ok {
		return
	} else {
		for rType, rByName := range resources {
			if isInternalKey(rType) {
				continue
			}
			byName, ok := asMap(rByName)
			if !ok {
				continue
			}
			for rName, rBody := range byName {
				if isInternalKey(rName) {
					continue
				}
				basePath := ddPath("resource", rType, rName)
				rootEntry := tfMakeEntry(rBody, docID, rType, rName, basePath, fm)
				rootOccID, rootKey := addEntryWithKey(index, rType, rName, rootEntry)
				indexTerraformKubernetesTargets(
					index, rBody, docID, rType, rName, basePath, rootOccID, rootKey, fm,
				)
			}
		}
	}
}

func indexTerraformData(index, doc map[string]interface{}, docID string, fm *model.FileMetadata) {
	data, ok := asMap(doc["data"])
	if !ok {
		return
	}
	for dType, dByName := range data {
		if isInternalKey(dType) {
			continue
		}
		byName, ok := asMap(dByName)
		if !ok {
			continue
		}
		indexedType := "data." + dType
		for dName, dBody := range byName {
			if isInternalKey(dName) {
				continue
			}
			addEntry(index, indexedType, dName, tfMakeEntry(dBody, docID, indexedType, dName, ddPath("data", dType, dName), fm))
		}
	}
}

func indexTerraformModules(index, doc map[string]interface{}, docID string, fm *model.FileMetadata) {
	modules, ok := asMap(doc["module"])
	if !ok {
		return
	}
	for mName, mBody := range modules {
		if isInternalKey(mName) {
			continue
		}
		addEntry(index, "module", mName, tfMakeEntry(mBody, docID, "module", mName, ddPath("module", mName), fm))
	}
}

func indexTerraformVariables(index, doc map[string]interface{}, docID string, fm *model.FileMetadata) {
	variables, ok := asMap(doc["variable"])
	if !ok {
		return
	}
	for vName, vBody := range variables {
		if isInternalKey(vName) {
			continue
		}
		addEntry(index, "variable", vName, tfMakeEntry(vBody, docID, "variable", vName, ddPath("variable", vName), fm))
	}
}

func indexTerraformOutputs(index, doc map[string]interface{}, docID string, fm *model.FileMetadata) {
	outputs, ok := asMap(doc["output"])
	if !ok {
		return
	}
	for oName, oBody := range outputs {
		if isInternalKey(oName) {
			continue
		}
		addEntry(index, "output", oName, tfMakeEntry(oBody, docID, "output", oName, ddPath("output", oName), fm))
	}
}

func indexTerraformProvidersBlock(index, doc map[string]interface{}, docID string, fm *model.FileMetadata) {
	providers, ok := asMap(doc["provider"])
	if !ok {
		return
	}
	for providerName, providerRaw := range providers {
		if isInternalKey(providerName) {
			continue
		}
		indexTerraformProviders(index, providerName, providerRaw, docID, fm)
	}
}

func indexTerraformProviders(
	index map[string]interface{}, providerName string, providerRaw interface{}, docID string, fm *model.FileMetadata,
) {
	provider, ok := asMap(providerRaw)
	if !ok {
		return
	}
	resourceType := "provider." + providerName
	if isProviderConfigBody(provider) {
		resourceName, _ := provider["alias"].(string)
		if resourceName == "" {
			resourceName = providerName
		}
		addEntry(index, resourceType, resourceName,
			tfMakeEntry(provider, docID, resourceType, resourceName, ddPath("provider", providerName), fm))
		return
	}
	for alias, aliasBody := range provider {
		if isInternalKey(alias) {
			continue
		}
		if body, ok := asMap(aliasBody); ok {
			addEntry(index, resourceType, alias,
				tfMakeEntry(body, docID, resourceType, alias, ddPath("provider", providerName, alias), fm))
		}
	}
}

func isProviderConfigBody(provider map[string]interface{}) bool {
	if len(provider) == 0 {
		return true
	}
	for key, value := range provider {
		if isInternalKey(key) {
			continue
		}
		if key == "alias" {
			return true
		}
		switch key {
		case "assume_role", "default_labels", "default_tags", "endpoints", "features", "ignore_tags":
			return true
		}
		if _, nested := asMap(value); !nested {
			return true
		}
	}
	return false
}

func indexTerraformKubernetesTargets(
	index map[string]interface{},
	rawResource interface{},
	docID, resourceType, resourceName string,
	basePath []interface{},
	rootOccID, rootKey string,
	fm *model.FileMetadata,
) {
	if _, ok := terraformKubernetesWorkloadTypes[resourceType]; !ok {
		return
	}
	resource, ok := asMap(rawResource)
	if !ok {
		return
	}

	for _, path := range [][]string{
		{"spec", "job_template", "spec", "template", "spec"},
		{"spec", "template", "spec"},
		{"spec"},
	} {
		nodes := mapNodesAtPath(resource, path)
		for _, node := range nodes {
			specPath := appendPath(basePath, node.path...)
			indexKubernetesPodSpec(index, node.value, docID, resourceType, resourceName, specPath,
				docID, "", terraformSourceScope(fm, docID), rootOccID, rootKey,
				"container", "init_container", "ephemeral_container")
		}
		if len(nodes) > 0 {
			return
		}
	}
}

func terraformSourceScope(file *model.FileMetadata, documentID string) string {
	if file != nil && file.FilePath != "" {
		return file.FilePath
	}
	return documentID
}

func tfMakeEntry(
	attrs interface{}, docID, resourceType, resourceName string, path []interface{}, fm *model.FileMetadata,
) map[string]interface{} {
	entry := makeEntry(attrs, docID, resourceType, resourceName, path)
	setEvalScope(entry, "module", terraformModuleScope(fm, docID, attrs))
	return entry
}

// Module instances scope by call chain; root files scope by directory.
func terraformModuleScope(fm *model.FileMetadata, docID string, attrs interface{}) string {
	if fm != nil && fm.ModuleCallChain != "" {
		return fm.ModuleCallChain
	}
	if m, ok := asMap(attrs); ok {
		if addr, ok := m["_dd_module_address"].(string); ok && addr != "" {
			return docID + "\x00" + addr
		}
	}
	if fm != nil && fm.Kind == model.KindTerraformPlan {
		return docID + "\x00"
	}
	if fm != nil && fm.FilePath != "" {
		return filepath.ToSlash(filepath.Dir(filepath.Clean(fm.FilePath)))
	}
	return docID
}
