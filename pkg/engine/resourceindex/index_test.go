/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resourceindex

import (
	"reflect"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// onlyEntry returns the single entry of a type bucket. The concrete map key is
// an internal, collision-safe identifier (it embeds the document id); rules
// only ever iterate a type bucket's values, so tests assert on the entry
// contents rather than on the key string.
func onlyEntry(t *testing.T, bucket map[string]interface{}) map[string]interface{} {
	t.Helper()
	if len(bucket) != 1 {
		t.Fatalf("expected exactly one entry, got %d: %v", len(bucket), bucket)
	}
	for _, v := range bucket {
		e, ok := v.(map[string]interface{})
		if !ok {
			t.Fatalf("entry is not a map: %T", v)
		}
		return e
	}
	return nil
}

func resourcePath(t *testing.T, entry map[string]interface{}) interface{} {
	t.Helper()
	metadata, ok := entry[EntryDD].(map[string]interface{})
	if !ok {
		t.Fatalf("entry has no %s metadata: %v", EntryDD, entry)
	}
	return metadata[EntryDDPath]
}

func resourceScope(t *testing.T, entry map[string]interface{}) string {
	t.Helper()
	metadata, ok := entry[EntryDD].(map[string]interface{})
	if !ok {
		t.Fatalf("entry has no %s metadata: %v", EntryDD, entry)
	}
	scope, ok := metadata[EntryDDScope].(string)
	if !ok {
		t.Fatalf("entry has no %s scope: %v", EntryDD, entry)
	}
	if _, exposed := entry["documentId"]; exposed {
		t.Fatalf("entry exposes documentId outside %s: %v", EntryDD, entry)
	}
	return scope
}

func buildIndex(t *testing.T, docs []interface{}, platformByDocID map[string]string) map[string]interface{} {
	t.Helper()
	filesMap := make(map[string]*model.FileMetadata, len(platformByDocID))
	for id, p := range platformByDocID {
		filesMap[id] = &model.FileMetadata{Platform: p}
	}
	return Build(docs, filesMap)
}

func TestBuildWithLookupSeparatesRuleAndScannerMetadata(t *testing.T) {
	docs := []interface{}{map[string]interface{}{
		"id": "tf1",
		"resource": map[string]interface{}{
			"aws_s3_bucket": map[string]interface{}{
				"bucket": map[string]interface{}{"acl": "private"},
			},
		},
	}}
	index, lookup := BuildWithLookup(docs, map[string]*model.FileMetadata{
		"tf1": {ID: "tf1", Platform: "terraform"},
	})
	entry := onlyEntry(t, index["aws_s3_bucket"].(map[string]interface{}))
	dd := ddOf(t, entry)
	if len(dd) != 1 || dd[EntryDDID] == "" {
		t.Fatalf("rule-visible _dd metadata is not opaque: %v", dd)
	}
	if entry[EntryCanonicalResourceType] != "aws_s3_bucket" ||
		entry[EntryCanonicalResourceName] != "bucket" {
		t.Fatalf("canonical identity missing from envelope: %v", entry)
	}
	attributes := entry[EntryAttributes].(map[string]interface{})
	if attributes["acl"] != "private" {
		t.Fatalf("source attributes missing from envelope: %v", attributes)
	}
	resourceID := dd[EntryDDID].(string)
	metadata := lookup[resourceID]
	wantPath := model.Path{
		{Key: "resource"},
		{Key: "aws_s3_bucket"},
		{Key: "bucket"},
	}
	if metadata.DocumentID != "tf1" || metadata.ResourceType != "aws_s3_bucket" ||
		metadata.ResourceName != "bucket" ||
		!reflect.DeepEqual(metadata.BasePath, wantPath) {
		t.Fatalf("scanner lookup metadata is incomplete: %+v", metadata)
	}
}

func TestOccurrenceIDPreservesTypedPathBoundaries(t *testing.T) {
	paths := [][]interface{}{
		{"a/b"},
		{"a", "b"},
		{"0"},
		{0},
	}
	ids := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		ids[makeOccurrenceID("document", path)] = struct{}{}
	}
	if len(ids) != len(paths) {
		t.Fatalf("resource identities collided: %v", ids)
	}
}

func ddOf(t *testing.T, entry map[string]interface{}) map[string]interface{} {
	t.Helper()
	dd, ok := entry[EntryDD].(map[string]interface{})
	if !ok {
		t.Fatalf("entry missing %s: %v", EntryDD, entry)
	}
	return dd
}

func evalScopesOf(t *testing.T, entry map[string]interface{}) map[string]interface{} {
	t.Helper()
	scopes, ok := ddOf(t, entry)[EntryDDEvaluationScopes].(map[string]interface{})
	if !ok {
		t.Fatalf("_dd missing %s", EntryDDEvaluationScopes)
	}
	return scopes
}

func relScopesOf(t *testing.T, entry map[string]interface{}) map[string]interface{} {
	t.Helper()
	scopes, ok := ddOf(t, entry)[EntryDDRelationshipScopes].(map[string]interface{})
	if !ok {
		t.Fatalf("_dd missing %s", EntryDDRelationshipScopes)
	}
	return scopes
}

func TestBuildResourceIndex_Terraform(t *testing.T) {
	docs := []interface{}{
		map[string]interface{}{
			"id": "tf1",
			"resource": map[string]interface{}{
				"_dd_lines": map[string]interface{}{"internal": true},
				"aws_s3_bucket": map[string]interface{}{
					"my_bucket": map[string]interface{}{
						"acl":             "private",
						"_dd_filter_expr": map[string]interface{}{"_op": "&&"},
						"_dd_lines":       map[string]interface{}{"internal": true},
					},
				},
			},
		},
	}
	filesMap := map[string]*model.FileMetadata{
		"tf1": {Platform: "terraform"},
	}
	index := Build(docs, filesMap)
	if index["_dd_lines"] != nil {
		t.Fatalf("parser metadata was indexed as a resource: %v", index["_dd_lines"])
	}

	bucket, ok := index["aws_s3_bucket"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected aws_s3_bucket bucket")
	}
	e := onlyEntry(t, bucket)
	if resourceScope(t, e) != "tf1" || e[EntryResourceType] != "aws_s3_bucket" || e[EntryResourceName] != "my_bucket" {
		t.Errorf("unexpected entry: %v", e)
	}
	wantPath := []interface{}{"resource", "aws_s3_bucket", "my_bucket"}
	if path := resourcePath(t, e); !reflect.DeepEqual(path, wantPath) {
		t.Errorf("_dd.path = %v, want %v", path, wantPath)
	}
	if metadata := e[EntryDD].(map[string]interface{}); metadata[EntryDDScope] != "tf1" ||
		metadata[EntryDDPlatform] != "terraform" {
		t.Errorf("unexpected _dd metadata: %v", metadata)
	}
	if e["_dd_filter_expr"] != nil || e["_dd_lines"] != nil {
		t.Errorf("entry exposes parser internals: %v", e)
	}
	if expression := e["filterExpression"].(map[string]interface{}); expression["operator"] != "&&" {
		t.Errorf("filter expression was not normalized: %v", e)
	}
	dd, ok := e[EntryDD].(map[string]interface{})
	if !ok {
		t.Fatalf("entry has no %s metadata: %v", EntryDD, e)
	}
	fieldMap, ok := dd[EntryDDFieldMap].(ProvenanceMap)
	if !ok {
		t.Fatalf("expected %s on indexed entry: %v", EntryDDFieldMap, e)
	}
	if fieldMap["filterExpression"] != "_dd_filter_expr" {
		t.Errorf("fieldMap[filterExpression] = %v, want _dd_filter_expr", fieldMap["filterExpression"])
	}
	if fieldMap["filterExpression.operator"] != "_op" {
		t.Errorf("fieldMap[filterExpression.operator] = %v, want _op", fieldMap["filterExpression.operator"])
	}
}

func TestBuildResourceIndex_CloudFormation(t *testing.T) {
	docs := []interface{}{
		map[string]interface{}{
			"id": "cf1",
			"Resources": map[string]interface{}{
				"MyBucket": map[string]interface{}{
					"Type": "AWS::S3::Bucket",
					"Properties": map[string]interface{}{
						"BucketName": "my-bucket",
					},
				},
				"WrappedProject": map[string]interface{}{
					"Project": map[string]interface{}{
						"Type":       "AWS::CodeBuild::Project",
						"Properties": map[string]interface{}{"Name": "build"},
					},
				},
			},
		},
	}
	filesMap := map[string]*model.FileMetadata{
		"cf1": {Platform: "cloudformation"},
	}
	index := Build(docs, filesMap)

	template := onlyEntry(t, index["cloudformation"].(map[string]interface{}))
	if resourceScope(t, template) != "cf1" || template[EntryResourceType] != "cloudformation" {
		t.Errorf("unexpected CloudFormation template entry: %v", template)
	}

	bucket, ok := index["AWS::S3::Bucket"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected AWS::S3::Bucket bucket; index keys: %v", mapKeys(index))
	}
	e := onlyEntry(t, bucket)
	if resourceScope(t, e) != "cf1" || e[EntryResourceType] != "AWS::S3::Bucket" || e[EntryResourceName] != "MyBucket" {
		t.Errorf("unexpected entry: %v", e)
	}
	project := onlyEntry(t, index["AWS::CodeBuild::Project"].(map[string]interface{}))
	wantProjectPath := []interface{}{"Resources", "WrappedProject", "Project"}
	if path := resourcePath(t, project); !reflect.DeepEqual(path, wantProjectPath) {
		t.Errorf("wrapped project path = %v, want %v", path, wantProjectPath)
	}
}

func TestBuildResourceIndex_Kubernetes(t *testing.T) {
	docs := []interface{}{
		map[string]interface{}{
			"id":   "k8s1",
			"kind": "Pod",
			"metadata": map[string]interface{}{
				"name": "my-pod",
			},
			"spec": map[string]interface{}{},
		},
	}
	filesMap := map[string]*model.FileMetadata{
		"k8s1": {Platform: "k8s", FilePath: "policies/audit.yaml"},
	}
	index := Build(docs, filesMap)

	bucket, ok := index["Pod"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected Pod bucket")
	}
	e := onlyEntry(t, bucket)
	if resourceScope(t, e) != "k8s1" || e[EntryResourceType] != "Pod" || e[EntryResourceName] != "my-pod" {
		t.Errorf("unexpected entry: %v", e)
	}
	if evalScopesOf(t, e)["source"] != "policies/audit.yaml" {
		t.Errorf("source scope missing: %v", e)
	}
}

func TestBuildResourceIndex_KubernetesCNIConfig(t *testing.T) {
	docs := []interface{}{
		map[string]interface{}{
			"id":         "cni1",
			"name":       "k8s-pod-network",
			"cniVersion": "0.3.0",
			"plugins": []interface{}{
				map[string]interface{}{"type": "flannel"},
			},
		},
	}
	index := Build(docs, map[string]*model.FileMetadata{})
	bucket, ok := index[K8sCNIConfigBucket].(map[string]interface{})
	if !ok {
		t.Fatalf("expected %s bucket", K8sCNIConfigBucket)
	}
	e := onlyEntry(t, bucket)
	if e[EntryResourceType] != K8sCNIConfigBucket || e[EntryResourceName] != "k8s-pod-network" {
		t.Errorf("unexpected entry: %v", e)
	}
	if evalScopesOf(t, e)["cluster"] != "scan" {
		t.Fatalf("cluster scope missing: %v", e)
	}
}

func TestBuildResourceIndex_KubernetesDocumentsShareClusterScope(t *testing.T) {
	docs := []interface{}{
		map[string]interface{}{
			"id": "k8s1", "apiVersion": "v1", "kind": "Service",
			"metadata": map[string]interface{}{"name": "api"},
		},
		map[string]interface{}{
			"id": "k8s2", "apiVersion": "v1", "kind": "Namespace",
			"metadata": map[string]interface{}{"name": "production"},
		},
	}
	filesMap := map[string]*model.FileMetadata{
		"k8s1": {Platform: "k8s", ScanID: "scan-1"},
		"k8s2": {Platform: "k8s", ScanID: "scan-1"},
	}

	index := Build(docs, filesMap)
	service := onlyEntry(t, index["Service"].(map[string]interface{}))
	namespace := onlyEntry(t, index["Namespace"].(map[string]interface{}))

	if evalScopesOf(t, service)["cluster"] != evalScopesOf(t, namespace)["cluster"] {
		t.Fatalf("Kubernetes documents have different cluster scopes")
	}
}

func TestBuildResourceIndex_KubernetesNestedTargets(t *testing.T) {
	docs := []interface{}{
		map[string]interface{}{
			"id":         "k8s1",
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata":   map[string]interface{}{"name": "api"},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{"name": "app", "image": "example/app:latest"},
						},
					},
				},
			},
		},
	}

	index := Build(docs, map[string]*model.FileMetadata{"k8s1": {Platform: "k8s"}})
	deployment := onlyEntry(t, index["Deployment"].(map[string]interface{}))
	podSpec := onlyEntry(t, index[K8sPodSpecBucket].(map[string]interface{}))
	if path := resourcePath(t, podSpec); !reflect.DeepEqual(path, []interface{}{"spec", "template", "spec"}) {
		t.Errorf("pod spec path = %v", path)
	}
	container := onlyEntry(t, index[K8sContainerBucket].(map[string]interface{}))
	if container[EntryResourceType] != "Deployment" || container[EntryResourceName] != "api" {
		t.Errorf("container lost parent identity: %v", container)
	}
	wantPath := []interface{}{"spec", "template", "spec", "containers", 0}
	if path := resourcePath(t, container); !reflect.DeepEqual(path, wantPath) {
		t.Errorf("container path = %v, want %v", path, wantPath)
	}
	rootKey := `k8s1#[]`
	podSpecKey := `k8s1#["spec","template","spec"]`
	if relScopesOf(t, deployment)[EntryRelationshipPodSpecKey] != podSpecKey {
		t.Errorf("deployment pod spec key = %v, want %s", relScopesOf(t, deployment), podSpecKey)
	}
	if relScopesOf(t, podSpec)[EntryRelationshipParentKey] != rootKey {
		t.Errorf("pod spec parent key = %v, want %s", relScopesOf(t, podSpec), rootKey)
	}
	if relScopesOf(t, container)[EntryRelationshipParentKey] != podSpecKey {
		t.Errorf("container parent key = %v, want %s", relScopesOf(t, container), podSpecKey)
	}
}

func TestBuildResourceIndex_KubernetesRelationshipKeysSurviveCollisions(t *testing.T) {
	workload := func(image string) map[string]interface{} {
		return map[string]interface{}{
			"id":         "k8s1",
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata":   map[string]interface{}{"name": "api"},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{"name": "app", "image": image},
						},
					},
				},
			},
		}
	}

	index := Build(
		[]interface{}{workload("example/first:latest"), workload("example/second:latest")},
		map[string]*model.FileMetadata{"k8s1": {Platform: "k8s"}},
	)
	deployments := index["Deployment"].(map[string]interface{})
	podSpecs := index[K8sPodSpecBucket].(map[string]interface{})
	containers := index[K8sContainerBucket].(map[string]interface{})

	rootKey := `k8s1#[]`
	podSpecKey := `k8s1#["spec","template","spec"]`
	containerKey := `k8s1#["spec","template","spec","containers",0]`
	for _, suffix := range []string{"", "#2"} {
		deployment := deployments[rootKey+suffix].(map[string]interface{})
		podSpec := podSpecs[podSpecKey+suffix].(map[string]interface{})
		container := containers[containerKey+suffix].(map[string]interface{})
		if got := relScopesOf(t, deployment)[EntryRelationshipPodSpecKey]; got != podSpecKey+suffix {
			t.Errorf("deployment pod spec key = %v, want %s", got, podSpecKey+suffix)
		}
		if got := relScopesOf(t, podSpec)[EntryRelationshipParentKey]; got != rootKey+suffix {
			t.Errorf("pod spec parent key = %v, want %s", got, rootKey+suffix)
		}
		if got := relScopesOf(t, container)[EntryRelationshipParentKey]; got != podSpecKey+suffix {
			t.Errorf("container parent key = %v, want %s", got, podSpecKey+suffix)
		}
	}
}

func TestBuildResourceIndex_KubernetesContainerProvenance(t *testing.T) {
	docs := []interface{}{map[string]interface{}{
		"id": "k8s1", "apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]interface{}{"name": "worker"},
		"spec": map[string]interface{}{
			"containers":          []interface{}{map[string]interface{}{"name": "main"}},
			"initContainers":      []interface{}{map[string]interface{}{"name": "setup"}},
			"ephemeralContainers": []interface{}{map[string]interface{}{"name": "debug"}},
		},
	}}
	index := Build(docs, map[string]*model.FileMetadata{"k8s1": {Platform: "kubernetes"}})
	containers := index[K8sContainerBucket].(map[string]interface{})
	if len(containers) != 3 {
		t.Fatalf("containers = %d, want 3", len(containers))
	}

	want := map[string]struct {
		field   string
		subtype string
		path    []interface{}
	}{
		"main":  {"containers", "container", []interface{}{"spec", "containers", 0}},
		"setup": {"initContainers", "init", []interface{}{"spec", "initContainers", 0}},
		"debug": {"ephemeralContainers", "ephemeral", []interface{}{"spec", "ephemeralContainers", 0}},
	}
	for _, raw := range containers {
		entry := raw.(map[string]interface{})
		containerName := entry["name"].(string)
		expected := want[containerName]
		if entry["containerField"] != expected.field || entry["containerType"] != expected.subtype {
			t.Errorf("%s metadata = %v", containerName, entry)
		}
		if !reflect.DeepEqual(entry["sourcePath"], expected.path) || entry["sourceScope"] == "" {
			t.Errorf("%s provenance = %v", containerName, entry)
		}
		attributes := entry[EntryAttributes].(map[string]interface{})
		if attributes["containerField"] != expected.field ||
			!reflect.DeepEqual(attributes["sourcePath"], expected.path) {
			t.Errorf("%s child attributes lost provenance: %v", containerName, attributes)
		}
	}
}

func TestBuildResourceIndex_TerraformKubernetesNestedTargets(t *testing.T) {
	docs := []interface{}{
		map[string]interface{}{
			"id": "tf1",
			"resource": map[string]interface{}{
				"kubernetes_deployment": map[string]interface{}{
					"api": map[string]interface{}{
						"spec": []interface{}{
							map[string]interface{}{
								"template": []interface{}{
									map[string]interface{}{
										"spec": []interface{}{
											map[string]interface{}{
												"container": []interface{}{
													map[string]interface{}{"name": "app", "image": "example/app:latest"},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	index := Build(docs, map[string]*model.FileMetadata{"tf1": {Platform: "terraform"}})
	podSpec := onlyEntry(t, index[K8sPodSpecBucket].(map[string]interface{}))
	container := onlyEntry(t, index[K8sContainerBucket].(map[string]interface{}))
	if container[EntryResourceType] != "kubernetes_deployment" || container[EntryResourceName] != "api" {
		t.Errorf("container lost Terraform parent identity: %v", container)
	}
	wantPath := []interface{}{
		"resource", "kubernetes_deployment", "api",
		"spec", 0, "template", 0, "spec", 0, "container", 0,
	}
	if path := resourcePath(t, container); !reflect.DeepEqual(path, wantPath) {
		t.Errorf("container path = %v, want %v", path, wantPath)
	}
	rootKey := `tf1#["resource","kubernetes_deployment","api"]`
	podSpecKey := `tf1#["resource","kubernetes_deployment","api","spec",0,"template",0,"spec",0]`
	if relScopesOf(t, podSpec)[EntryRelationshipParentKey] != rootKey {
		t.Errorf("pod spec parent key = %v, want %s", relScopesOf(t, podSpec), rootKey)
	}
	if relScopesOf(t, container)[EntryRelationshipParentKey] != podSpecKey {
		t.Errorf("container parent key = %v, want %s", relScopesOf(t, container), podSpecKey)
	}
}

func TestBuildResourceIndex_TerraformKubernetesV1Workload(t *testing.T) {
	docs := []interface{}{
		map[string]interface{}{
			"id": "tf1",
			"resource": map[string]interface{}{
				"kubernetes_deployment_v1": map[string]interface{}{
					"api": map[string]interface{}{
						"spec": []interface{}{
							map[string]interface{}{
								"template": []interface{}{
									map[string]interface{}{
										"spec": []interface{}{
											map[string]interface{}{
												"container": []interface{}{
													map[string]interface{}{"name": "app", "image": "example/app:latest"},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	index := Build(docs, map[string]*model.FileMetadata{"tf1": {Platform: "terraform"}})
	container := onlyEntry(t, index[K8sContainerBucket].(map[string]interface{}))
	if container[EntryResourceType] != "kubernetes_deployment_v1" || container[EntryResourceName] != "api" {
		t.Errorf("container lost Terraform v1 parent identity: %v", container)
	}
}

func TestBuildResourceIndex_Dockerfile(t *testing.T) {
	docs := []interface{}{
		map[string]interface{}{
			"id": "df1",
			"command": map[string]interface{}{
				"ubuntu:latest": []interface{}{
					map[string]interface{}{"Cmd": "from", "Value": []interface{}{"ubuntu:latest"}},
				},
			},
		},
	}
	filesMap := map[string]*model.FileMetadata{
		"df1": {Platform: "dockerfile"},
	}
	index := Build(docs, filesMap)

	fromBucket, ok := index["FROM"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected FROM bucket; index keys: %v", mapKeys(index))
	}
	e := onlyEntry(t, fromBucket)
	if resourceScope(t, e) != "df1" || e[EntryResourceType] != "FROM" {
		t.Errorf("from entry: %v", e)
	}
	instructionScope := e[EntryScope].(map[string]interface{})
	if instructionScope["source"] != "df1" || instructionScope["document"] != nil {
		t.Errorf("unexpected Dockerfile instruction scope: %v", instructionScope)
	}
	if e[EntryResourceName] != "dockerfile" {
		t.Errorf("unstable Dockerfile instruction name: %v", e)
	}
	if e["stageName"] != "ubuntu:latest" || e["stageOrdinal"] != 0 ||
		e["baseImage"] != "ubuntu:latest" || e["stageAlias"] != "" ||
		e["instructionIndex"] != 0 {
		t.Errorf("unexpected Dockerfile instruction metadata: %v", e)
	}

	rootBucket, ok := index["dockerfile"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected dockerfile root bucket")
	}
	root := onlyEntry(t, rootBucket)
	if root[EntryResourceName] != "dockerfile" {
		t.Errorf("unexpected dockerfile root entry: %v", rootBucket)
	}
	rootScope := root[EntryScope].(map[string]interface{})
	if rootScope["source"] != "df1" || rootScope["document"] != nil {
		t.Errorf("unexpected Dockerfile root scope: %v", rootScope)
	}
}

func TestBuildResourceIndex_CICD(t *testing.T) {
	docs := []interface{}{
		map[string]interface{}{
			"id":    "ci1",
			"file":  "/private/workflows/ci.yaml",
			"_path": "/private/workflows/ci.yaml",
			"name":  "My Workflow",
			"on":    map[string]interface{}{"push": nil},
			"jobs": map[string]interface{}{
				"build": map[string]interface{}{
					"permissions": map[string]interface{}{"contents": "read"},
					"steps": []interface{}{
						map[string]interface{}{
							"name":        "Test",
							"run":         "go test ./...",
							"_parsed_run": map[string]interface{}{"parse_ok": true},
							"_dd_lines":   map[string]interface{}{"internal": true},
						},
						map[string]interface{}{"uses": "actions/checkout@v4"},
						map[string]interface{}{"id": "compile", "run": "go build ./..."},
						map[string]interface{}{"name": "Pinned", "run": "go test ./..."},
					},
					"services": map[string]interface{}{
						"postgres": map[string]interface{}{"image": "postgres:16"},
					},
				},
				"test": map[string]interface{}{
					"steps": []interface{}{
						map[string]interface{}{"name": "step3", "run": "echo c"},
					},
				},
			},
			"updates": []interface{}{
				map[string]interface{}{"package-ecosystem": "gomod", "directory": "/"},
			},
		},
	}
	index := Build(docs, map[string]*model.FileMetadata{"ci1": {Platform: "cicd"}})

	workflow := onlyEntry(t, index["github_action"].(map[string]interface{}))
	if resourceScope(t, workflow) != "ci1" || workflow[EntryResourceName] != "My Workflow" {
		t.Errorf("unexpected workflow entry: %v", workflow)
	}
	if workflow["file"] != nil || workflow["_path"] != nil {
		t.Errorf("CICD entry exposes internal paths: %v", workflow)
	}

	jobBucket := index["github_job"].(map[string]interface{})
	var job map[string]interface{}
	for _, raw := range jobBucket {
		entry := raw.(map[string]interface{})
		if entry[EntryResourceName] == "build" {
			job = entry
			break
		}
	}
	if job == nil || job[EntryResourceName] != "build" {
		t.Fatalf("build job missing: %v", jobBucket)
	}

	steps := index["github_step"].(map[string]interface{})
	if len(steps) != 5 {
		t.Fatalf("steps = %d, want 5", len(steps))
	}
	stepNames := make(map[string]bool)
	for _, raw := range steps {
		entry := raw.(map[string]interface{})
		stepNames[entry[EntryResourceName].(string)] = true
		if entry[EntryResourceName] == "Test" {
			if entry["_parsed_run"] != nil || entry["_dd_lines"] != nil {
				t.Errorf("step exposes parser internals: %v", entry)
			}
			wantPath := []interface{}{"jobs", "build", "steps", 0}
			if path := resourcePath(t, entry); !reflect.DeepEqual(path, wantPath) {
				t.Errorf("step path = %v, want %v", path, wantPath)
			}
		}
	}
	for _, name := range []string{"build/step:1", "compile", "Pinned", "Test", "step3"} {
		if !stepNames[name] {
			t.Errorf("missing stable step name %q: %v", name, stepNames)
		}
	}

	services := index["github_service"].(map[string]interface{})
	if len(services) != 1 {
		t.Fatalf("services = %d, want 1", len(services))
	}
	updates := index["dependabot_update"].(map[string]interface{})
	if len(updates) != 1 {
		t.Fatalf("updates = %d, want 1", len(updates))
	}
}

func TestBuildResourceIndex_Ansible(t *testing.T) {
	docs := []interface{}{
		map[string]interface{}{
			"id":  "ans1",
			"all": map[string]interface{}{"hosts": map[string]interface{}{}},
			"groups": map[string]interface{}{
				"defaults": map[string]interface{}{"ansible_user": "root"},
			},
			"playbooks": []interface{}{
				map[string]interface{}{
					"name":  "install nginx",
					"tasks": []interface{}{},
				},
			},
		},
	}
	filesMap := map[string]*model.FileMetadata{
		"ans1": {Platform: "ansible"},
	}
	index := Build(docs, filesMap)

	config, ok := index["ansible.config"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected ansible.config bucket")
	}
	if onlyEntry(t, config)[EntryResourceType] != "ansible_config" {
		t.Errorf("unexpected config entry: %v", config)
	}
	if _, ok := index["ansible_group"]; ok {
		t.Fatal("config groups must not be indexed under a second identity")
	}

	inv, ok := index["ansible_inventory"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected ansible_inventory bucket")
	}
	if onlyEntry(t, inv)[EntryResourceType] != "ansible_inventory" {
		t.Errorf("unexpected inventory entry: %v", inv)
	}
	if onlyEntry(t, inv)[EntryResourceName] != "inventory" {
		t.Errorf("unstable inventory resource name: %v", inv)
	}

	pb, ok := index["ansible_playbook"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected ansible_playbook bucket")
	}
	pbEntry := onlyEntry(t, pb)
	if resourceScope(t, pbEntry) != "ans1" || pbEntry[EntryResourceType] != "ansible_playbook" {
		t.Errorf("unexpected playbook entry: %v", pbEntry)
	}

	docs = []interface{}{
		map[string]interface{}{
			"id": "ans1",
			"playbooks": []interface{}{
				map[string]interface{}{
					"tasks": []interface{}{
						map[string]interface{}{
							"name": "outer",
							"block": []interface{}{
								map[string]interface{}{"name": "nested", "debug": map[string]interface{}{"msg": "hello"}},
							},
						},
						map[string]interface{}{"name": "configure", "debug": map[string]interface{}{"msg": "first"}},
						map[string]interface{}{"name": "configure", "debug": map[string]interface{}{"msg": "second"}},
					},
					"pre_tasks": []interface{}{
						map[string]interface{}{
							"name":                "install package",
							"ansible.builtin.apt": map[string]interface{}{"name": "nginx"},
						},
					},
				},
			},
		},
	}
	index = Build(docs, map[string]*model.FileMetadata{"ans1": {Platform: "ansible"}})
	tasks := index["ansible_task"].(map[string]interface{})
	if len(tasks) != 5 {
		t.Fatalf("expected nested and duplicate tasks; got %d", len(tasks))
	}
	modules := index["ansible.module"].(map[string]interface{})
	if len(modules) < 1 {
		t.Fatalf("expected module invocation: %v", modules)
	}
}

func TestBuildResourceIndex_AnsibleCanonicalModules(t *testing.T) {
	docs := []interface{}{map[string]interface{}{
		"id": "ans1",
		"playbooks": []interface{}{map[string]interface{}{
			"name": "configure",
			"tasks": []interface{}{
				map[string]interface{}{
					"name":              "upload object",
					"amazon.aws.aws_s3": `bucket=assets object="release archive.zip"`,
				},
				map[string]interface{}{
					"name":   "open port",
					"action": `amazon.aws.ec2_security_group name=web description="web access"`,
				},
				map[string]interface{}{
					"name":                "install package",
					"args":                map[string]interface{}{"state": "latest"},
					"ansible.builtin.apt": map[string]interface{}{"name": "nginx"},
				},
				map[string]interface{}{
					"name":    "generic yaml",
					"entries": []interface{}{"one", "two"},
				},
			},
		}},
	}}
	index := Build(docs, map[string]*model.FileMetadata{"ans1": {Platform: "ansible"}})

	s3 := onlyEntry(t, index["s3_object"].(map[string]interface{}))
	if s3[EntryResourceName] != "release archive.zip" ||
		s3["moduleName"] != "s3_object" ||
		s3["originalModuleName"] != "amazon.aws.aws_s3" ||
		s3["taskOrder"] != 0 {
		t.Fatalf("unexpected historical alias entry: %v", s3)
	}
	securityGroup := onlyEntry(t, index["ec2_group"].(map[string]interface{}))
	if securityGroup[EntryResourceName] != "web" ||
		securityGroup["originalModuleName"] != "amazon.aws.ec2_security_group" {
		t.Fatalf("unexpected action entry: %v", securityGroup)
	}
	apt := onlyEntry(t, index["apt"].(map[string]interface{}))
	if apt["state"] != "latest" || apt[EntryResourceName] != "nginx" || apt["taskOrder"] != 2 {
		t.Fatalf("task args were not merged: %v", apt)
	}
	if len(index["ansible.module"].(map[string]interface{})) != 3 {
		t.Fatalf("generic YAML list was indexed as a module: %v", index["ansible.module"])
	}
	if relScopesOf(t, apt)["task"] == "" || relScopesOf(t, apt)["play"] == "" {
		t.Fatalf("module relationships are incomplete: %v", apt)
	}
}

func TestBuildResourceIndex_DuplicateNamesAcrossDocuments(t *testing.T) {
	docs := []interface{}{
		map[string]interface{}{
			"id":       "first",
			"resource": map[string]interface{}{"aws_s3_bucket": map[string]interface{}{"logs": map[string]interface{}{"acl": "private"}}},
		},
		map[string]interface{}{
			"id":       "second",
			"resource": map[string]interface{}{"aws_s3_bucket": map[string]interface{}{"logs": map[string]interface{}{"acl": "private"}}},
		},
	}
	files := map[string]*model.FileMetadata{
		"first":  {Platform: "terraform"},
		"second": {Platform: "terraform"},
	}

	bucket := Build(docs, files)["aws_s3_bucket"].(map[string]interface{})
	if len(bucket) != 2 {
		t.Fatalf("same-name resources collided: %v", bucket)
	}
	for _, raw := range bucket {
		entry := raw.(map[string]interface{})
		if entry[EntryResourceName] != "logs" {
			t.Errorf("compound key leaked into resource name: %v", entry)
		}
	}
}

// TestBuildResourceIndex_Scopes checks evaluation and relationship scopes on indexed entries.
func TestBuildResourceIndex_Scopes(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		index := buildIndex(t, []interface{}{
			map[string]interface{}{
				"id": "tf1",
				"resource": map[string]interface{}{
					"aws_s3_bucket": map[string]interface{}{"b": map[string]interface{}{"acl": "private"}},
				},
			},
		}, map[string]string{"tf1": "terraform"})
		for _, entry := range index["aws_s3_bucket"].(map[string]interface{}) {
			dd := ddOf(t, entry.(map[string]interface{}))
			if dd[EntryDDResourceID] == "" || dd[EntryDDDocumentID] == "" {
				t.Fatalf("entry missing ids: %v", dd)
			}
			if dd[EntryDDScope] != dd[EntryDDDocumentID] {
				t.Fatalf("scope != documentId: %v", dd)
			}
		}
	})

	t.Run("kubernetes_namespace_and_parent", func(t *testing.T) {
		index := buildIndex(t, []interface{}{
			map[string]interface{}{
				"id": "k8s1", "kind": "Deployment", "apiVersion": "apps/v1",
				"metadata": map[string]interface{}{"name": "myapp", "namespace": "prod"},
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{"name": "main", "image": "nginx"},
							},
						},
					},
				},
			},
		}, map[string]string{"k8s1": "kubernetes"})
		rootID, _ := ddOf(t, onlyEntry(t, index["Deployment"].(map[string]interface{})))[EntryDDResourceID].(string)
		podSpec := onlyEntry(t, index[K8sPodSpecBucket].(map[string]interface{}))
		if evalScopesOf(t, podSpec)["namespace"] != "prod" {
			t.Fatalf("namespace scope missing: %v", podSpec)
		}
		container := onlyEntry(t, index[K8sContainerBucket].(map[string]interface{}))
		if relScopesOf(t, container)["parent"] != ddOf(t, podSpec)[EntryDDResourceID] {
			t.Fatalf("container parent scope wrong")
		}
		if rootID == "" {
			t.Fatal("root deployment missing resourceId")
		}
	})
}

func TestBuildResourceIndex_TerraformModuleScopeSharedAcrossFiles(t *testing.T) {
	docs := []interface{}{
		map[string]interface{}{
			"id": "main-doc",
			"resource": map[string]interface{}{
				"aws_s3_bucket": map[string]interface{}{
					"logs": map[string]interface{}{"bucket": "my-logs"},
				},
			},
		},
		map[string]interface{}{
			"id": "vars-doc",
			"resource": map[string]interface{}{
				"aws_s3_bucket_acl": map[string]interface{}{
					"logs": map[string]interface{}{"bucket": "aws_s3_bucket.logs.id"},
				},
			},
		},
	}
	files := map[string]*model.FileMetadata{
		"main-doc": {Platform: "terraform", FilePath: "stack/main.tf"},
		"vars-doc": {Platform: "terraform", FilePath: "stack/variables.tf"},
	}
	index := Build(docs, files)
	bucketScope, _ := evalScopesOf(t, onlyEntry(t, index["aws_s3_bucket"].(map[string]interface{})))["module"].(string)
	aclScope, _ := evalScopesOf(t, onlyEntry(t, index["aws_s3_bucket_acl"].(map[string]interface{})))["module"].(string)
	if bucketScope != aclScope {
		t.Fatalf("resources in the same module dir have different scopes: %q vs %q", bucketScope, aclScope)
	}
	if bucketScope != "stack" {
		t.Fatalf("module scope = %q, want stack", bucketScope)
	}
}

func TestBuildResourceIndex_TerraformPlanScopesAreDocumentLocal(t *testing.T) {
	docs := []interface{}{
		map[string]interface{}{
			"id": "plan-one",
			"resource": map[string]interface{}{
				"aws_s3_bucket": map[string]interface{}{
					"logs": map[string]interface{}{"bucket": "first"},
				},
			},
		},
		map[string]interface{}{
			"id": "plan-two",
			"resource": map[string]interface{}{
				"aws_s3_bucket_acl": map[string]interface{}{
					"logs": map[string]interface{}{"bucket": "aws_s3_bucket.logs.id"},
				},
			},
		},
	}
	files := map[string]*model.FileMetadata{
		"plan-one": {Platform: "terraform", Kind: model.KindTerraformPlan, FilePath: "stack/one.json"},
		"plan-two": {Platform: "terraform", Kind: model.KindTerraformPlan, FilePath: "stack/two.json"},
	}

	index := Build(docs, files)
	bucketScope, _ := evalScopesOf(t, onlyEntry(t, index["aws_s3_bucket"].(map[string]interface{})))["module"].(string)
	aclScope, _ := evalScopesOf(t, onlyEntry(t, index["aws_s3_bucket_acl"].(map[string]interface{})))["module"].(string)
	if bucketScope == aclScope {
		t.Fatalf("independent plans share module scope %q", bucketScope)
	}
	if bucketScope != "plan-one\x00" || aclScope != "plan-two\x00" {
		t.Fatalf("unexpected plan scopes: %q and %q", bucketScope, aclScope)
	}
}

func TestBuildResourceIndex_TerraformModelDocument(t *testing.T) {
	docs := []interface{}{
		model.Document{
			"id": "tf2",
			"resource": model.Document{
				"aws_security_group": model.Document{
					"allow_tls": model.Document{
						"ingress": model.Document{
							"from_port": float64(22),
							"to_port":   float64(22),
							"protocol":  "tcp",
						},
					},
				},
			},
		},
	}
	filesMap := map[string]*model.FileMetadata{
		"tf2": {Platform: "terraform"},
	}
	index := Build(docs, filesMap)

	bucket, ok := index["aws_security_group"].(map[string]interface{})
	if !ok {
		t.Fatalf("aws_security_group bucket missing — model.Document type assertion broke indexing")
	}
	e := onlyEntry(t, bucket)
	if resourceScope(t, e) != "tf2" || e[EntryResourceType] != "aws_security_group" || e[EntryResourceName] != "allow_tls" {
		t.Errorf("unexpected entry: %v", e)
	}
}

// mapKeys returns the keys of a map for error messages.
func mapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
