/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import (
	"context"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	dockerParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/docker"
	terraformParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	defaultYaml "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/default"
	"github.com/stretchr/testify/require"
)

const sampleTF = `
resource "aws_s3_bucket" "b" {
  bucket = "my-bucket"
}

data "aws_ami" "example" {
  most_recent = true
}

module "network" {
  source  = "./modules/network"
  version = "~> 2.0"
}
`

// parseTF parses Terraform source into a FileMetadata the way the scanner does.
func parseTF(t *testing.T, name, content string) *model.FileMetadata {
	t.Helper()
	p := terraformParser.NewDefault()
	_, docs, _, _, err := p.Parse(context.Background(), []byte(content), name, true, 15)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	return &model.FileMetadata{
		FilePath: name,
		Kind:     model.KindTerraform,
		Document: docs[0],
	}
}

const sampleK8s = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: prod
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25
---
apiVersion: v1
kind: Service
metadata:
  name: my-svc
spec:
  ports:
    - port: 80
`

// parseYAML parses a (possibly multi-document) YAML file into one FileMetadata
// per document, the way the scanner does.
func parseYAML(t *testing.T, name, content string) model.FileMetadatas {
	t.Helper()
	p := &defaultYaml.Parser{}
	_, docs, _, _, err := p.Parse(context.Background(), []byte(content), name, true, 15)
	require.NoError(t, err)
	files := make(model.FileMetadatas, 0, len(docs))
	for _, doc := range docs {
		files = append(files, &model.FileMetadata{
			FilePath:         name,
			Kind:             model.KindYAML,
			Document:         doc,
			LineInfoDocument: doc,
		})
	}
	return files
}

// parseDockerfile parses a Dockerfile into a FileMetadata the way the scanner does.
func parseDockerfile(t *testing.T, name, content string) model.FileMetadatas {
	t.Helper()
	p := &dockerParser.Parser{}
	_, docs, _, _, err := p.Parse(context.Background(), []byte(content), name, true, 15)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	return model.FileMetadatas{{
		FilePath:         name,
		Kind:             model.KindDOCKER,
		Document:         docs[0],
		LineInfoDocument: docs[0],
	}}
}

func findResource(resources []Resource, blockType BlockType, name string) (Resource, bool) {
	for _, r := range resources {
		if r.BlockType == blockType && r.Name == name {
			return r, true
		}
	}
	return Resource{}, false
}

func TestWalkFiles_Terraform(t *testing.T) {
	files := model.FileMetadatas{parseTF(t, "main.tf", sampleTF)}
	resources := WalkFiles(files, nil)

	require.Len(t, resources, 3)

	bucket, ok := findResource(resources, BlockResource, "b")
	require.True(t, ok, "expected aws_s3_bucket resource")
	require.Equal(t, platformTerraform, bucket.Platform)
	require.Equal(t, "aws_s3_bucket", bucket.Type)
	require.Equal(t, "aws", bucket.Provider)
	require.Equal(t, "main.tf", bucket.File)
	require.Greater(t, bucket.StartLine, 0, "resource should carry a start line")
	require.GreaterOrEqual(t, bucket.EndLine, bucket.StartLine, "end line should be >= start line")

	data, ok := findResource(resources, BlockData, "example")
	require.True(t, ok, "expected aws_ami data source")
	require.Equal(t, "aws_ami", data.Type)
	require.Equal(t, "aws", data.Provider)

	mod, ok := findResource(resources, BlockModule, "network")
	require.True(t, ok, "expected network module")
	require.Empty(t, mod.Type)
	require.Empty(t, mod.Provider)
	require.Equal(t, "./modules/network", mod.ModuleSource)
	require.Equal(t, "~> 2.0", mod.ModuleVersion)
}

func TestWalkFiles_SkipsNonTerraform(t *testing.T) {
	files := model.FileMetadatas{
		{FilePath: "k8s.yaml", Kind: model.KindYAML, Document: model.Document{"kind": "Pod"}},
		{FilePath: "empty.tf", Kind: model.KindTerraform, Document: model.Document{}},
	}
	require.Empty(t, WalkFiles(files, nil))
}

func TestBuildInventory(t *testing.T) {
	files := model.FileMetadatas{parseTF(t, "main.tf", sampleTF)}
	inv := BuildInventory(WalkFiles(files, nil), "my-repo")

	require.Equal(t, SchemaVersion, inv.SchemaVersion)
	require.Equal(t, "Datadog", inv.Tool.Vendor)
	require.NotEmpty(t, inv.GeneratedAt)
	require.Equal(t, "my-repo", inv.RootPath)
	require.Equal(t, 3, inv.ResourceCount)
	require.Len(t, inv.Resources, 3)

	var bucket *InventoryEntry
	for i := range inv.Resources {
		if inv.Resources[i].Address == "aws_s3_bucket.b" {
			bucket = &inv.Resources[i]
			break
		}
	}
	require.NotNil(t, bucket, "expected entry for the s3 bucket")
	require.Equal(t, "terraform", bucket.IaCPlatform)
	require.Equal(t, "resource", bucket.BlockType)
	require.NotNil(t, bucket.ResourceType)
	require.Equal(t, "aws_s3_bucket", *bucket.ResourceType)
	require.Equal(t, "b", bucket.Name)
	require.Equal(t, "aws", bucket.Provider)
	require.Equal(t, "main.tf", bucket.FilePath)
	require.Greater(t, bucket.LineRange.Start, 0)
	require.GreaterOrEqual(t, bucket.LineRange.End, bucket.LineRange.Start)
	require.NotNil(t, bucket.Attributes, "attributes must be populated")
	require.Equal(t, "my-bucket", bucket.Attributes["bucket"], "bucket attribute should be extracted")
	for k := range bucket.Attributes {
		require.False(t, strings.HasPrefix(k, "_dd_"), "attributes must not contain _dd_ keys, found: %s", k)
	}

	// data resource attributes
	var dataEntry *InventoryEntry
	for i := range inv.Resources {
		if inv.Resources[i].Address == "data.aws_ami.example" {
			dataEntry = &inv.Resources[i]
			break
		}
	}
	require.NotNil(t, dataEntry)
	require.NotNil(t, dataEntry.Attributes)
	_, hasMostRecent := dataEntry.Attributes["most_recent"]
	require.True(t, hasMostRecent, "most_recent attribute should be present")

	// module entries must have null resource_type
	var modEntry *InventoryEntry
	for i := range inv.Resources {
		if inv.Resources[i].Address == "module.network" {
			modEntry = &inv.Resources[i]
			break
		}
	}
	require.NotNil(t, modEntry)
	require.Nil(t, modEntry.ResourceType, "module entries should have null resource_type")
	require.Equal(t, "./modules/network", modEntry.ModuleSource)
	require.Equal(t, "~> 2.0", modEntry.ModuleVersion)
}

func TestResourceAddress(t *testing.T) {
	addr := func(r Resource) string { return resourceAddress(&r) }
	require.Equal(t, "aws_s3_bucket.b",
		addr(Resource{BlockType: BlockResource, Type: "aws_s3_bucket", Name: "b"}))
	require.Equal(t, "data.aws_ami.example",
		addr(Resource{BlockType: BlockData, Type: "aws_ami", Name: "example"}))
	require.Equal(t, "module.network",
		addr(Resource{BlockType: BlockModule, Name: "network"}))
	require.Equal(t, "prod/Deployment/my-app",
		addr(Resource{BlockType: BlockManifest, Type: "Deployment", Name: "my-app", Namespace: "prod"}))
	require.Equal(t, "Service/my-svc",
		addr(Resource{BlockType: BlockManifest, Type: "Service", Name: "my-svc"}))
}

func TestWalkFiles_Kubernetes(t *testing.T) {
	resources := WalkFiles(parseYAML(t, "deploy.yaml", sampleK8s), nil)
	require.Len(t, resources, 2)

	dep, ok := findResource(resources, BlockManifest, "my-app")
	require.True(t, ok, "expected Deployment manifest")
	require.Equal(t, platformKubernetes, dep.Platform)
	require.Equal(t, "Deployment", dep.Type)
	require.Equal(t, "apps/v1", dep.APIVersion)
	require.Equal(t, "prod", dep.Namespace)
	require.Empty(t, dep.Provider)
	require.Equal(t, "deploy.yaml", dep.File)
	require.Greater(t, dep.StartLine, 0, "manifest should carry a start line")
	require.GreaterOrEqual(t, dep.EndLine, dep.StartLine, "end line should be >= start line")

	require.NotNil(t, dep.Attributes)
	require.Equal(t, "Deployment", dep.Attributes["kind"])
	require.Contains(t, dep.Attributes, "spec")
	for _, injected := range []string{"_path", "id", "file"} {
		require.NotContains(t, dep.Attributes, injected, "injected key must be stripped")
	}
	for k := range dep.Attributes {
		require.False(t, strings.HasPrefix(k, "_dd_"), "attributes must not contain _dd_ keys, found: %s", k)
	}

	svc, ok := findResource(resources, BlockManifest, "my-svc")
	require.True(t, ok, "expected Service manifest")
	require.Equal(t, "Service", svc.Type)
	require.Empty(t, svc.Namespace)
}

func TestBuildInventory_Kubernetes(t *testing.T) {
	inv := BuildInventory(WalkFiles(parseYAML(t, "deploy.yaml", sampleK8s), nil), "my-repo")
	require.Equal(t, 2, inv.ResourceCount)

	var dep *InventoryEntry
	for i := range inv.Resources {
		if inv.Resources[i].Address == "prod/Deployment/my-app" {
			dep = &inv.Resources[i]
			break
		}
	}
	require.NotNil(t, dep, "expected entry addressed prod/Deployment/my-app")
	require.Equal(t, "kubernetes", dep.IaCPlatform)
	require.Equal(t, "manifest", dep.BlockType)
	require.NotNil(t, dep.ResourceType)
	require.Equal(t, "Deployment", *dep.ResourceType)
	require.Equal(t, "apps/v1", dep.APIVersion)
	require.Equal(t, "prod", dep.Namespace)
	require.Empty(t, dep.Provider)
}

func TestWalkFiles_SkipsNonKubernetesYAML(t *testing.T) {
	files := model.FileMetadatas{
		{FilePath: "vars.yaml", Kind: model.KindYAML, Document: model.Document{"foo": "bar"}, LineInfoDocument: map[string]interface{}{"foo": "bar"}},
	}
	require.Empty(t, WalkFiles(files, nil))
}

const sampleCFN = `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-cfn-bucket
  MyQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: my-queue
`

func TestWalkFiles_CloudFormation(t *testing.T) {
	resources := WalkFiles(parseYAML(t, "template.yaml", sampleCFN), nil)
	require.Len(t, resources, 2)

	bucket, ok := findResource(resources, BlockResource, "MyBucket")
	require.True(t, ok, "expected MyBucket resource")
	require.Equal(t, platformCloudFormation, bucket.Platform)
	require.Equal(t, "AWS::S3::Bucket", bucket.Type)
	require.Equal(t, "aws", bucket.Provider)
	require.Greater(t, bucket.StartLine, 0)
	require.GreaterOrEqual(t, bucket.EndLine, bucket.StartLine)
	require.Equal(t, "my-cfn-bucket", attrMap(t, bucket.Attributes, "Properties")["BucketName"])

	inv := BuildInventory(resources, "repo")
	var addrs []string
	for _, e := range inv.Resources {
		addrs = append(addrs, e.Address)
	}
	require.Contains(t, addrs, "MyBucket")
}

const sampleAnsible = `---
- name: configure web servers
  hosts: web
  tasks:
    - name: install nginx
      ansible.builtin.package:
        name: nginx
        state: present
    - name: start nginx
      ansible.builtin.service:
        name: nginx
        state: started
    - name: grouped
      block:
        - name: write config
          ansible.builtin.copy:
            src: nginx.conf
            dest: /etc/nginx/nginx.conf
`

func TestWalkFiles_Ansible(t *testing.T) {
	resources := WalkFiles(parseYAML(t, "playbook.yaml", sampleAnsible), nil)
	require.Len(t, resources, 3, "two top-level tasks plus one inside the block")

	install, ok := findResource(resources, BlockTask, "install nginx")
	require.True(t, ok)
	require.Equal(t, platformAnsible, install.Platform)
	require.Equal(t, "ansible.builtin.package", install.Type)
	require.Greater(t, install.StartLine, 0)
	require.Equal(t, "present", attrMap(t, install.Attributes, "ansible.builtin.package")["state"])

	_, ok = findResource(resources, BlockTask, "write config")
	require.True(t, ok, "task nested in a block should be walked")
}

const sampleDockerfile = `FROM golang:1.22 AS builder
WORKDIR /src
COPY . .
RUN go build -o app

FROM alpine:3.19
COPY --from=builder /src/app /app
ENTRYPOINT ["/app"]
`

func TestWalkFiles_Dockerfile(t *testing.T) {
	resources := WalkFiles(parseDockerfile(t, "Dockerfile", sampleDockerfile), nil)
	require.Len(t, resources, 2, "two build stages")

	builder, ok := findResource(resources, BlockStage, "builder")
	require.True(t, ok, "expected the aliased builder stage")
	require.Equal(t, platformDockerfile, builder.Platform)
	require.Equal(t, "golang:1.22", builder.Type, "base image should be the resource type")
	require.Greater(t, builder.StartLine, 0)
	require.GreaterOrEqual(t, builder.EndLine, builder.StartLine)

	runtime, ok := findResource(resources, BlockStage, "alpine:3.19")
	require.True(t, ok, "unaliased stage should be named by its image")
	require.Equal(t, "alpine:3.19", runtime.Type)
}

const sampleWorkflow = `name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make build
  test:
    runs-on: ubuntu-latest
    steps:
      - run: make test
`

func TestWalkFiles_CICD(t *testing.T) {
	resources := WalkFiles(parseYAML(t, ".github/workflows/ci.yaml", sampleWorkflow), nil)
	require.Len(t, resources, 2, "two jobs")

	build, ok := findResource(resources, BlockJob, "build")
	require.True(t, ok)
	require.Equal(t, platformCICD, build.Platform)
	require.Greater(t, build.StartLine, 0)
	for k := range build.Attributes {
		require.False(t, strings.HasPrefix(k, "_parsed"), "parser enrichments must be stripped, found: %s", k)
	}

	_, ok = findResource(resources, BlockJob, "test")
	require.True(t, ok)
}

func TestWalkFiles_GatesOnEnabledPlatforms(t *testing.T) {
	files := append(parseTFFiles(t, "main.tf", sampleTF), parseYAML(t, "deploy.yaml", sampleK8s)...)

	// Only Terraform enabled: Kubernetes manifests are excluded.
	tfOnly := WalkFiles(files, []string{"Terraform"})
	require.NotEmpty(t, tfOnly)
	for _, r := range tfOnly {
		require.Equal(t, platformTerraform, r.Platform)
	}

	// Only Kubernetes enabled (case-insensitive): Terraform is excluded.
	k8sOnly := WalkFiles(files, []string{"kubernetes"})
	require.NotEmpty(t, k8sOnly)
	for _, r := range k8sOnly {
		require.Equal(t, platformKubernetes, r.Platform)
	}

	// No filter enables everything.
	require.Equal(t, len(tfOnly)+len(k8sOnly), len(WalkFiles(files, nil)))
}

const sampleDependabot = `version: 2
updates:
  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "daily"
  - package-ecosystem: "npm"
    directory: "/frontend"
    schedule:
      interval: "weekly"
`

func TestWalkFiles_CICD_Dependabot(t *testing.T) {
	resources := WalkFiles(parseYAML(t, ".github/dependabot.yaml", sampleDependabot), nil)
	require.Len(t, resources, 2, "one resource per update entry")

	var gomod, npm *Resource
	for i := range resources {
		switch resources[i].Type {
		case "gomod":
			gomod = &resources[i]
		case "npm":
			npm = &resources[i]
		}
	}
	require.NotNil(t, gomod, "expected gomod update")
	require.Equal(t, platformCICD, gomod.Platform)
	require.Equal(t, BlockJob, gomod.BlockType)
	require.Equal(t, "/", gomod.Name, "name falls back to directory when set")

	require.NotNil(t, npm, "expected npm update")
	require.Equal(t, "/frontend", npm.Name)
}

const sampleCompositeAction = `name: My Composite Action
description: does things
runs:
  using: composite
  steps:
    - run: echo hello
      shell: bash
`

func TestWalkFiles_CICD_CompositeAction(t *testing.T) {
	resources := WalkFiles(parseYAML(t, "action.yaml", sampleCompositeAction), nil)
	require.Len(t, resources, 1)

	action := resources[0]
	require.Equal(t, platformCICD, action.Platform)
	require.Equal(t, BlockJob, action.BlockType)
	require.Equal(t, "composite-action", action.Type)
	require.Equal(t, "My Composite Action", action.Name)
	require.Greater(t, action.StartLine, 0)
}

func TestResourceAddress_AllBlockTypes(t *testing.T) {
	addr := func(r Resource) string { return resourceAddress(&r) }

	require.Equal(t, "install nginx",
		addr(Resource{BlockType: BlockTask, Name: "install nginx", Type: "ansible.builtin.package"}))
	require.Equal(t, "ansible.builtin.package",
		addr(Resource{BlockType: BlockTask, Name: "", Type: "ansible.builtin.package"}))
	require.Equal(t, "builder",
		addr(Resource{BlockType: BlockStage, Name: "builder"}))
	require.Equal(t, "build",
		addr(Resource{BlockType: BlockJob, Name: "build"}))
	require.Equal(t, "MyBucket",
		addr(Resource{BlockType: BlockResource, Platform: platformCloudFormation, Name: "MyBucket", Type: "AWS::S3::Bucket"}))
}

func TestCFNProvider(t *testing.T) {
	require.Equal(t, "aws", cfnProvider("AWS::S3::Bucket"))
	require.Equal(t, "custom", cfnProvider("Custom::MyThing"))
	require.Equal(t, "nonamespace", cfnProvider("NoNamespace"))
	require.Empty(t, cfnProvider(""))
}

func TestStartLine_Forms(t *testing.T) {
	lo := model.LineObject{Line: 42}
	loPtr := &lo

	bodyStructForm := map[string]interface{}{
		ddLinesKey: map[string]model.LineObject{ddDefaultKey: lo},
	}
	require.Equal(t, 42, startLine(bodyStructForm))

	bodyPtrForm := map[string]interface{}{
		ddLinesKey: map[string]*model.LineObject{ddDefaultKey: loPtr},
	}
	require.Equal(t, 42, startLine(bodyPtrForm))

	bodyGeneric := map[string]interface{}{
		ddLinesKey: map[string]interface{}{
			ddDefaultKey: map[string]interface{}{"_dd_line": float64(7)},
		},
	}
	require.Equal(t, 7, startLine(bodyGeneric))

	require.Equal(t, 0, startLine(map[string]interface{}{}))
	require.Equal(t, 0, startLine("not a map"))
}

func TestLineFromGeneric(t *testing.T) {
	lo := model.LineObject{Line: 10}
	loPtr := &lo

	require.Equal(t, 10, lineFromGeneric(lo))
	require.Equal(t, 10, lineFromGeneric(loPtr))
	require.Equal(t, 0, lineFromGeneric((*model.LineObject)(nil)))
	require.Equal(t, 5, lineFromGeneric(map[string]interface{}{"_dd_line": float64(5)}))
	require.Equal(t, 0, lineFromGeneric("unexpected"))
}

func TestWalkTypedBlocks_ListBodies(t *testing.T) {
	// When a type maps to a list of bodies, each body gets a synthetic
	// indexed name to avoid a malformed "type." address.
	doc := model.Document{
		"resource": map[string]interface{}{
			"aws_security_group": []interface{}{
				map[string]interface{}{"description": "sg1"},
				map[string]interface{}{"description": "sg2"},
			},
		},
	}
	resources := walkTypedBlocks("f.tf", doc, "resource", BlockResource)
	require.Len(t, resources, 2)
	require.Equal(t, "aws_security_group[0]", resources[0].Name)
	require.Equal(t, "aws_security_group[1]", resources[1].Name)
	for _, r := range resources {
		require.Equal(t, "aws_security_group", r.Type)
		require.Equal(t, "aws", r.Provider)
	}
}

func TestCleanAttrs_AnnotationMapDropped(t *testing.T) {
	annotationMap := map[string]model.LineObject{"field": {Line: 1}}
	require.Nil(t, cleanAttrs(annotationMap))

	ptrMap := map[string]*model.LineObject{"field": {Line: 1}}
	require.Nil(t, cleanAttrs(ptrMap))
}

func TestAttrsFromBody_NonMap(t *testing.T) {
	require.Nil(t, attrsFromBody("a string"))
	require.Nil(t, attrsFromBody(nil))
}

func TestIntFromNumber(t *testing.T) {
	n, ok := intFromNumber(int(5))
	require.True(t, ok)
	require.Equal(t, 5, n)

	n, ok = intFromNumber(float64(3.0))
	require.True(t, ok)
	require.Equal(t, 3, n)

	_, ok = intFromNumber("not a number")
	require.False(t, ok)
}

func TestGenericLine_IntForm(t *testing.T) {
	line, ok := genericLine(map[string]interface{}{"_dd_line": int(12)})
	require.True(t, ok)
	require.Equal(t, 12, line)

	_, ok = genericLine(map[string]interface{}{"_dd_line": "not a number"})
	require.False(t, ok)
}

func TestWalkLineObjects_WithArr(t *testing.T) {
	lo := model.LineObject{
		Line: 5,
		Arr: []map[string]*model.LineObject{
			{"elem": {Line: 9}},
			{"other": nil},
		},
	}
	m := map[string]model.LineObject{"field": lo}
	tracker := &lineTracker{}
	tracker.walkLineObjects(m)
	require.Equal(t, 5, tracker.min)
	require.Equal(t, 9, tracker.max)
}

func TestStringAttr_MissingAndNonString(t *testing.T) {
	require.Empty(t, stringAttr(nil, "key"))
	require.Empty(t, stringAttr(map[string]interface{}{"key": 42}, "key"))
	require.Equal(t, "val", stringAttr(map[string]interface{}{"key": "val"}, "key"))
}

func TestProviderFromType_NoUnderscore(t *testing.T) {
	require.Equal(t, "justtype", providerFromType("justtype"))
	require.Empty(t, providerFromType(""))
}

func TestK8sNameAndNamespace_NoMetadata(t *testing.T) {
	name, ns := k8sNameAndNamespace(model.Document{})
	require.Empty(t, name)
	require.Empty(t, ns)
}

func TestNewPlatformSet_EmptyPlatform(t *testing.T) {
	ps := newPlatformSet([]string{""})
	require.True(t, ps.all, "an empty string in the list should enable all platforms")
}

// parseTFFiles wraps parseTF as a FileMetadatas slice for combining with other platforms.
func parseTFFiles(t *testing.T, name, content string) model.FileMetadatas {
	t.Helper()
	return model.FileMetadatas{parseTF(t, name, content)}
}

// attrMap fetches a nested map attribute, failing the test when it is absent.
func attrMap(t *testing.T, attrs map[string]interface{}, key string) map[string]interface{} {
	t.Helper()
	require.NotNil(t, attrs)
	m, ok := attrs[key].(map[string]interface{})
	require.True(t, ok, "expected attribute %q to be a map", key)
	return m
}
