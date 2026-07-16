/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resourceindex

var k8sClusterScopedKinds = map[string]struct{}{
	"Namespace":                      {},
	"Node":                           {},
	"PersistentVolume":               {},
	"ClusterRole":                    {},
	"ClusterRoleBinding":             {},
	"CustomResourceDefinition":       {},
	"APIService":                     {},
	"StorageClass":                   {},
	"PriorityClass":                  {},
	"MutatingWebhookConfiguration":   {},
	"ValidatingWebhookConfiguration": {},
	"CSIDriver":                      {},
	"CSINode":                        {},
	"VolumeAttachment":               {},
	"RuntimeClass":                   {},
}

func indexKubernetesDoc(index, doc map[string]interface{}, docID, clusterScope, source string) {
	kind, _ := doc["kind"].(string)
	if kind == "" {
		// CNI configs have cniVersion but no Kubernetes kind.
		indexKubernetesCNIConfig(index, doc, docID, clusterScope)
		return
	}

	resourceName := ""
	if meta, ok := doc["metadata"].(map[string]interface{}); ok {
		resourceName, _ = meta["name"].(string)
	}
	if resourceName == "" {
		resourceName = kind
	}

	namespace := k8sNamespace(doc, kind)

	rootEntry := makeEntry(publicDocumentAttrs(doc), docID, kind, resourceName, ddPath())
	setEvalScope(rootEntry, "cluster", clusterScope)
	setEvalScope(rootEntry, "source", source)
	if namespace != "" {
		setEvalScope(rootEntry, "namespace", namespace)
	}
	rootOccID, rootKey := addEntryWithKey(index, kind, resourceName, rootEntry)

	spec, specPath, ok := nativeKubernetesPodSpec(doc, kind)
	if !ok {
		return
	}
	podSpecKey := indexKubernetesPodSpec(index, spec, docID, kind, resourceName, specPath,
		clusterScope, namespace, source, rootOccID, rootKey,
		"containers", "initContainers", "ephemeralContainers")
	if podSpecKey != "" {
		setRelScope(rootEntry, EntryRelationshipPodSpecKey, podSpecKey)
	}
}

func indexKubernetesCNIConfig(index, doc map[string]interface{}, docID, clusterScope string) {
	if doc["cniVersion"] == nil {
		return
	}
	resourceName, _ := doc["name"].(string)
	if resourceName == "" {
		resourceName = "cni"
	}
	entry := makeEntry(publicDocumentAttrs(doc), docID, K8sCNIConfigBucket, resourceName, ddPath())
	setEvalScope(entry, "cluster", clusterScope)
	addEntry(index, K8sCNIConfigBucket, resourceName, entry)
}

// Namespaced resources use "default" when metadata.namespace is absent.
func k8sNamespace(doc map[string]interface{}, kind string) string {
	if _, clusterScoped := k8sClusterScopedKinds[kind]; clusterScoped {
		return ""
	}
	if meta, ok := doc["metadata"].(map[string]interface{}); ok {
		if ns, _ := meta["namespace"].(string); ns != "" {
			return ns
		}
	}
	return "default"
}

func indexKubernetesPodSpec(
	index map[string]interface{},
	spec map[string]interface{},
	docID, resourceType, resourceName string,
	specPath []interface{},
	clusterScope, namespace, source, parentOccID string,
	parentKey string,
	containerFields ...string,
) string {
	podSpecEntry := makeEntry(spec, docID, resourceType, resourceName, specPath)
	setEvalScope(podSpecEntry, "cluster", clusterScope)
	setEvalScope(podSpecEntry, "source", source)
	if namespace != "" {
		setEvalScope(podSpecEntry, "namespace", namespace)
	}
	if parentOccID != "" {
		setRelScope(podSpecEntry, "parent", parentOccID)
	}
	if parentKey != "" {
		setRelScope(podSpecEntry, EntryRelationshipParentKey, parentKey)
	}
	podSpecOccID, podSpecKey := addEntryWithKey(index, K8sPodSpecBucket, resourceName, podSpecEntry)

	for _, field := range containerFields {
		subtype := kubernetesContainerSubtype(field)
		for _, node := range mapNodesAtPath(spec, []string{field}) {
			containerName, _ := node.value["name"].(string)
			if containerName == "" {
				containerName = resourceName
			}
			containerEntry := makeEntry(node.value, docID, resourceType, resourceName, appendPath(specPath, node.path...))
			sourcePath := appendPath(specPath, node.path...)
			setEntryField(containerEntry, "sourceScope", parentOccID)
			setEntryField(containerEntry, "sourcePath", sourcePath)
			setEntryField(containerEntry, "containerType", subtype)
			setEntryField(containerEntry, "containerField", field)
			setEvalScope(containerEntry, "cluster", clusterScope)
			setEvalScope(containerEntry, "source", source)
			if namespace != "" {
				setEvalScope(containerEntry, "namespace", namespace)
			}
			parentID := podSpecOccID
			if parentID == "" {
				parentID = parentOccID
			}
			if parentID != "" {
				setRelScope(containerEntry, "parent", parentID)
			}
			directParentKey := podSpecKey
			if directParentKey == "" {
				directParentKey = parentKey
			}
			if directParentKey != "" {
				setRelScope(containerEntry, EntryRelationshipParentKey, directParentKey)
			}
			addEntry(index, K8sContainerBucket, containerName, containerEntry)
		}
	}
	return podSpecKey
}

func kubernetesContainerSubtype(field string) string {
	switch field {
	case "initContainers", "init_container":
		return "init"
	case "ephemeralContainers", "ephemeral_container":
		return "ephemeral"
	default:
		return "container"
	}
}
