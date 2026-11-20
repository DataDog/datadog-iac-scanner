/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package scan

import (
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/inventory"
	"github.com/stretchr/testify/require"
)

const inventoryK8sYAML = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: shop
spec:
  replicas: 1
---
# the service
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: shop
spec:
  ports:
    - port: 80
`

const inventoryDockerfile = `FROM golang:1.23 AS build
WORKDIR /src
COPY . .
RUN go build -o /out/api ./cmd/api

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/api /api
EXPOSE 8080
ENTRYPOINT ["/api"]
`

func documentParams(root string) *Parameters {
	return &Parameters{
		Path:             []string{root},
		RepoPath:         root,
		QueriesPath:      []string{"."},
		PreviewLines:     3,
		CloudProvider:    []string{""},
		Platform:         []string{"Kubernetes", "Dockerfile"},
		ScanID:           "console",
		MaxFileSizeFlag:  100,
		MaxResolverDepth: 15,
		FlagEvaluator:    featureflags.NewLocalEvaluator(),
	}
}

func TestInventoryKubernetesAndDockerfileRows(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"k8s/web.yaml":                         inventoryK8sYAML,
		"charts/api/Chart.yaml":                "apiVersion: v2\nname: api\nversion: 0.1.0\n",
		"charts/api/values.yaml":               "replicas: 2\n",
		"charts/api/templates/deployment.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .Release.Name }}-{{ .Chart.Name }}\nspec:\n  replicas: {{ .Values.replicas }}\n",
		"services/api/Dockerfile":              inventoryDockerfile,
		// A template rendered by another tool: its name stays as written.
		"dev/manifest.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .ServiceName }}\nspec:\n  replicas: 1\n",
		// A resource created with a generated name.
		"k8s/migrate.yaml": "apiVersion: batch/v1\nkind: Job\nmetadata:\n  generateName: migrate-\n  namespace: shop\nspec:\n  template:\n    spec:\n      restartPolicy: Never\n",
	})
	inv := scanInventory(t, documentParams(root))
	rows := rowsByPath(inv)

	require.Equal(t, inventory.Resource{
		ResourceRef:  "k8s/web.yaml|apps/v1/Deployment/shop/web",
		ResourcePath: "apps/v1/Deployment/shop/web",
		Platform:     "kubernetes",
		ResourceType: "Deployment",
		ResourceName: "web",
		File:         "k8s/web.yaml",
		LineStart:    1,
		LineEnd:      7,
		Completeness: inventory.CompletenessComplete,
	}, rows["apps/v1/Deployment/shop/web"])

	service := rows["v1/Service/shop/web"]
	require.Equal(t, lineOf(t, inventoryK8sYAML, "apiVersion: v1"), service.LineStart)
	require.Equal(t, lineOf(t, inventoryK8sYAML, "- port: 80"), service.LineEnd)

	helm, ok := rows["apps/v1/Deployment//dd-helm-api"]
	require.True(t, ok, "rows: %v", rows)
	require.Equal(t, inventory.Resource{
		ResourceRef:        "charts/api/templates/deployment.yaml|apps/v1/Deployment//dd-helm-api",
		ResourcePath:       "apps/v1/Deployment//dd-helm-api",
		Platform:           "kubernetes",
		ResourceType:       "Deployment",
		ResourceName:       "dd-helm-api",
		File:               "charts/api/templates/deployment.yaml",
		LineStart:          1,
		Completeness:       inventory.CompletenessComplete,
		OriginGenerator:    "helm",
		OriginChartPath:    "charts/api",
		OriginChartName:    "api",
		OriginChartVersion: "0.1.0",
		OriginTemplate:     "templates/deployment.yaml",
	}, helm)

	require.Equal(t, inventory.Resource{
		ResourceRef:  "services/api/Dockerfile|Dockerfile",
		ResourcePath: "Dockerfile",
		Platform:     "dockerfile",
		ResourceType: "dockerfile",
		ResourceName: "Dockerfile",
		File:         "services/api/Dockerfile",
		LineStart:    1,
		LineEnd:      lineOf(t, inventoryDockerfile, "ENTRYPOINT"),
		Completeness: inventory.CompletenessComplete,
	}, rows["Dockerfile"])
	templated := rows["apps/v1/Deployment//{{ .ServiceName }}"]
	require.Equal(t, "{{ .ServiceName }}", templated.ResourceName)
	require.Equal(t, "dev/manifest.yaml", templated.File)
	generated, ok := rows["batch/v1/Job/shop/migrate-"]
	require.True(t, ok, "a generated name gives its prefix: %v", rows)
	require.Equal(t, "migrate-", generated.ResourceName)
	require.Equal(t, 1, generated.LineStart)
	require.Len(t, inv.Resources, 6)
}

func TestInventoryDoesNotChangeDocumentFindings(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"k8s/web.yaml":            inventoryK8sYAML,
		"services/api/Dockerfile": inventoryDockerfile,
	})
	without := scanSARIF(t, *documentParams(root))
	with := *documentParams(root)
	with.InventoryPath = filepath.Join(t.TempDir(), "inventory.json")
	require.Equal(t, without, scanSARIF(t, with))
}

const inventoryPlaybook = `- hosts: all
  tasks:
    - name: Install nginx
      ansible.builtin.apt:
        name: nginx
    - block:
        - name: Start nginx
          ansible.builtin.service:
            name: nginx
  handlers:
    - name: restart nginx
      ansible.builtin.service:
        name: nginx
        state: restarted
- hosts: db
  tasks:
    - ansible.builtin.ping:
`

func TestInventoryKeyedRows(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"cfn/stack.yaml": "AWSTemplateFormatVersion: \"2010-09-09\"\nResources:\n  LogsBucket:\n    Type: AWS::S3::Bucket\n" +
			"    Properties:\n      BucketName: acme-logs\n\n  Queue:\n    Type: AWS::SQS::Queue\n" +
			// A section after the collection is not part of its last entry.
			"Parameters:\n  Env:\n    Type: String\n    Default: prod\n",
		"docker-compose.yml": "services:\n  web:\n    image: nginx:1.27\n  db:\n    image: postgres:16\n",
		".github/workflows/ci.yml": "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make test\n" +
			"  _lint:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.sha }}\n" +
			"  _dd_build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n",
		"site.yml":                 inventoryPlaybook,
		"roles/web/tasks/main.yml": "- name: Copy config\n  ansible.builtin.copy:\n    src: a\n    dest: b\n" +
			"- name: Copy by action\n  action: ansible.builtin.copy src=a dest=b\n" +
			"- name: Echo locally\n  local_action: ansible.builtin.command echo hello\n" +
			"- name: Copy by mapping\n  action:\n    module: ansible.builtin.copy\n    src: a\n",
		// A list the scanner reads as Ansible tasks, outside any tasks
		// directory: not a task file.
		"data/cities.yml": "- name: Paris\n  country: FR\n- name: Madrid\n  country: ES\n",
	})
	params := documentParams(root)
	params.Platform = []string{"CloudFormation", "DockerCompose", "CICD", "Ansible"}
	inv := scanInventory(t, params)

	type want struct {
		ref, typ, name string
		start, end     int
	}
	got := make(map[string]want, len(inv.Resources))
	for _, r := range inv.Resources {
		got[r.ResourceRef] = want{r.ResourceRef, r.ResourceType, r.ResourceName, r.LineStart, r.LineEnd}
	}
	for _, w := range []want{
		{"cfn/stack.yaml|LogsBucket", "AWS::S3::Bucket", "acme-logs", 3, 6},
		{"cfn/stack.yaml|Queue", "AWS::SQS::Queue", "Queue", 8, 9},
		{"docker-compose.yml|services.web", "docker_compose_service", "web", 2, 3},
		{"docker-compose.yml|services.db", "docker_compose_service", "db", 4, 5},
		{".github/workflows/ci.yml|jobs.build", "github_actions_job", "build", 3, 6},
		{".github/workflows/ci.yml|jobs.test", "github_actions_job", "test", 7, 10},
		// A job ID can start with an underscore, even like a scanner key.
		{".github/workflows/ci.yml|jobs._lint", "github_actions_job", "_lint", 11, 14},
		{".github/workflows/ci.yml|jobs._dd_build", "github_actions_job", "_dd_build", 15, 18},
		{"site.yml|plays[0].tasks[0]", "ansible.builtin.apt", "Install nginx", 3, 5},
		{"site.yml|plays[0].tasks[1].block[0]", "ansible.builtin.service", "Start nginx", 7, 9},
		{"site.yml|plays[0].handlers[0]", "ansible.builtin.service", "restart nginx", 11, 14},
		{"site.yml|plays[1].tasks[0]", "ansible.builtin.ping", "ansible.builtin.ping", 17, 17},
		{"roles/web/tasks/main.yml|tasks[0]", "ansible.builtin.copy", "Copy config", 1, 4},
		// The module an action or local_action names, not the keyword.
		{"roles/web/tasks/main.yml|tasks[1]", "ansible.builtin.copy", "Copy by action", 5, 6},
		{"roles/web/tasks/main.yml|tasks[2]", "ansible.builtin.command", "Echo locally", 7, 8},
		{"roles/web/tasks/main.yml|tasks[3]", "ansible.builtin.copy", "Copy by mapping", 9, 12},
	} {
		require.Equal(t, w, got[w.ref], w.ref)
	}
	require.Len(t, inv.Resources, 16)
	require.Contains(t, inv.Files, inventory.File{Path: "data/cities.yml", Platform: "ansible", Status: inventory.FileScanned},
		"the list is scanned as Ansible, yet gives no row")
	for _, r := range inv.Resources {
		if r.Platform == inventory.PlatformCloudFormation {
			require.Equal(t, "aws", r.Provider)
		}
	}
}
