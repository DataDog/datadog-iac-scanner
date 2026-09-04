/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import "github.com/DataDog/datadog-iac-scanner/pkg/model"

const platformKubernetes = "kubernetes"

// kubernetesWalker matches Kubernetes (and Knative/Crossplane) manifests by
// the defining apiVersion/kind pair.
type kubernetesWalker struct{}

func (kubernetesWalker) Platform() string { return platformKubernetes }

func (kubernetesWalker) Kinds() []model.FileKind {
	return []model.FileKind{model.KindYAML, model.KindYML, model.KindJSON}
}

func (kubernetesWalker) Walk(filePath string, doc model.Document) ([]Resource, bool) {
	r, ok := walkKubernetesDocument(filePath, doc)
	if !ok {
		return nil, false
	}
	return []Resource{r}, true
}

// walkKubernetesDocument returns ok=false when apiVersion or kind is absent.
func walkKubernetesDocument(filePath string, doc model.Document) (Resource, bool) {
	apiVersion, _ := doc["apiVersion"].(string)
	kind, _ := doc["kind"].(string)
	if apiVersion == "" || kind == "" {
		return Resource{}, false
	}

	name, namespace := k8sNameAndNamespace(doc)
	start, end := lineBounds(doc)

	attrs := attrsFromBody(doc)
	deleteInjectedKeys(attrs)

	return Resource{
		Platform:   platformKubernetes,
		BlockType:  BlockManifest,
		Type:       kind,
		Name:       name,
		File:       filePath,
		StartLine:  start,
		EndLine:    end,
		APIVersion: apiVersion,
		Namespace:  namespace,
		Attributes: attrs,
	}, true
}

func k8sNameAndNamespace(doc model.Document) (name, namespace string) {
	metadata, ok := toMap(doc["metadata"])
	if !ok {
		return "", ""
	}
	name, _ = metadata["name"].(string)
	namespace, _ = metadata["namespace"].(string)
	return name, namespace
}
