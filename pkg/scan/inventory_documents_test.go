/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package scan

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/platforms"

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
		// A comment after it is not part of the name.
		"dev/worker.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .WorkerName }} # deployment-time name\nspec:\n  replicas: 1\n",
		// A templated name written in a flow mapping, and one over two lines.
		"dev/flow.yaml":      "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: {{ .FlowName }}, namespace: prod}\nspec:\n  replicas: 1\n",
		"dev/multiline.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{\n    .LongName }}\nspec:\n  replicas: 1\n",
		// A resource created with a generated name.
		"k8s/migrate.yaml": "apiVersion: batch/v1\nkind: Job\nmetadata:\n  generateName: migrate-\n  namespace: shop\nspec:\n  template:\n    spec:\n      restartPolicy: Never\n",
		// A list holds separate objects, each its own resource.
		"k8s/list.yaml": "apiVersion: v1\nkind: List\nitems:\n  - apiVersion: v1\n    kind: ConfigMap\n    metadata:\n      name: settings\n" +
			"    data:\n      a: \"1\"\n  - apiVersion: v1\n    kind: Service\n    metadata:\n      name: api\n      namespace: shop\n",
		// A typed list gives its members the kind and version they omit.
		"k8s/pods.yaml": "apiVersion: v1\nkind: PodList\nitems:\n  - metadata:\n      name: web\n    spec:\n      containers: []\n",
		// A list in a list holds objects too.
		"k8s/nested.yaml": "apiVersion: v1\nkind: List\nitems:\n  - apiVersion: v1\n    kind: List\n    items:\n" +
			"      - apiVersion: v1\n        kind: ConfigMap\n        metadata:\n          name: inner\n",
		// A member's templated name is taken as written, as an object's is.
		"k8s/templated-list.yaml": "apiVersion: v1\nkind: List\nitems:\n  - apiVersion: v1\n    kind: ConfigMap\n" +
			"    metadata:\n      name: {{ .SettingsName }} # rendered later\n",
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
	commented, ok := rows["apps/v1/Deployment//{{ .WorkerName }}"]
	require.True(t, ok, "a trailing comment stays out of the name: %v", rows)
	require.Equal(t, "{{ .WorkerName }}", commented.ResourceName)
	flow, ok := rows["apps/v1/Deployment/prod/{{ .FlowName }}"]
	require.True(t, ok, "a flow-style templated name stops at its closing brace: %v", rows)
	require.Equal(t, "{{ .FlowName }}", flow.ResourceName)
	multiline, ok := rows["apps/v1/Deployment//{{\n    .LongName }}"]
	require.True(t, ok, "a multiline templated name is kept whole, as written: %v", rows)
	require.Equal(t, "dev/multiline.yaml", multiline.File)
	generated, ok := rows["batch/v1/Job/shop/migrate-"]
	require.True(t, ok, "a generated name gives its prefix: %v", rows)
	require.Equal(t, "migrate-", generated.ResourceName)
	require.Equal(t, 1, generated.LineStart)
	settings, api := rows["v1/ConfigMap//settings"], rows["v1/Service/shop/api"]
	require.Equal(t, "k8s/list.yaml", settings.File)
	require.Equal(t, [2]int{4, 9}, [2]int{settings.LineStart, settings.LineEnd})
	require.Equal(t, [2]int{10, 14}, [2]int{api.LineStart, api.LineEnd})
	pod, ok := rows["v1/Pod//web"]
	require.True(t, ok, "a typed list member: %v", rows)
	require.Equal(t, [2]int{4, 7}, [2]int{pod.LineStart, pod.LineEnd})
	inner, ok := rows["v1/ConfigMap//inner"]
	require.True(t, ok, "a member of a nested list: %v", rows)
	require.Equal(t, [2]int{7, 10}, [2]int{inner.LineStart, inner.LineEnd})
	templatedMember, ok := rows["v1/ConfigMap//{{ .SettingsName }}"]
	require.True(t, ok, "a list member with a templated name: %v", rows)
	require.Equal(t, "k8s/templated-list.yaml", templatedMember.File)
	require.Len(t, inv.Resources, 14)
}

func TestInventoryKeepsAFailedChartRender(t *testing.T) {
	// The parent's values make its dependency fail; the dependency's own
	// defaults do not, so the dependency renders on its own.
	root := writeRepo(t, map[string]string{
		"charts/parent/Chart.yaml":             "apiVersion: v2\nname: parent\nversion: 0.1.0\n",
		"charts/parent/values.yaml":            "dep:\n  shared:\n    fail: true\n",
		"charts/parent/charts/dep/Chart.yaml":  "apiVersion: v2\nname: dep\nversion: 0.1.0\n",
		"charts/parent/charts/dep/values.yaml": "shared:\n  fail: false\n",
		"charts/parent/charts/dep/templates/cm.yaml": "{{- if .Values.shared.fail }}{{ fail \"not in this configuration\" }}{{- end }}\n" +
			"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: dep-config\ndata:\n  a: b\n",
	})
	params := documentParams(root)
	params.Platform = []string{"Kubernetes"}
	inv := scanInventory(t, params)

	names := make([]string, 0, len(inv.Resources))
	for _, r := range inv.Resources {
		names = append(names, r.ResourceName)
	}
	require.Contains(t, names, "dep-config", "the dependency rendered on its own")
	require.Equal(t, inventory.StatusPartial, inv.Status, "the parent's render failed")
	require.Contains(t, inv.UnresolvedSources, inventory.UnresolvedSource{
		Platform: platforms.Kubernetes, Source: "charts/parent", Reason: inventory.ReasonHelmRenderFailed,
	})
	for _, u := range inv.UnresolvedSources {
		require.NotEqual(t, "charts/parent/charts/dep", u.Source, "the dependency rendered on its own")
	}
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
		// Services merged in from an anchor, one named like parser metadata.
		"merged/docker-compose.yml": "x-services: &services\n  _parsed_expressions_web:\n    image: nginx:1.27\n  regular:\n    image: alpine:3\n" +
			"services:\n  <<: *services\n",
		".github/workflows/ci.yml": "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make test\n" +
			"  _lint:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.sha }}\n" +
			"  _dd_build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n" +
			"  _parsed_expressions_release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make release\n",
		"site.yml": inventoryPlaybook,
		"roles/web/tasks/main.yml": "- name: Copy config\n  ansible.builtin.copy:\n    src: a\n    dest: b\n" +
			"- name: Copy by action\n  action: ansible.builtin.copy src=a dest=b\n" +
			"- name: Echo locally\n  local_action: ansible.builtin.command echo hello\n" +
			"- name: Copy by mapping\n  action:\n    module: ansible.builtin.copy\n    src: a\n" +
			// become_exe is a keyword, sorted before the module.
			"- name: Escalate\n  become_exe: /usr/bin/sudo\n  shell: echo example\n" +
			"- name: Escalate fully\n  become_exe: /usr/bin/sudo\n  ansible.builtin.shell: echo example\n",
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
		// The file spells the merge, not the services: they are at the collection.
		{"merged/docker-compose.yml|services._parsed_expressions_web", "docker_compose_service", "_parsed_expressions_web", 6, 0},
		{"merged/docker-compose.yml|services.regular", "docker_compose_service", "regular", 6, 0},
		{".github/workflows/ci.yml|jobs.build", "github_actions_job", "build", 3, 6},
		{".github/workflows/ci.yml|jobs.test", "github_actions_job", "test", 7, 10},
		// A job ID can start with an underscore, even like a scanner key.
		{".github/workflows/ci.yml|jobs._lint", "github_actions_job", "_lint", 11, 14},
		{".github/workflows/ci.yml|jobs._dd_build", "github_actions_job", "_dd_build", 15, 18},
		{".github/workflows/ci.yml|jobs._parsed_expressions_release", "github_actions_job", "_parsed_expressions_release", 19, 22},
		{"site.yml|plays[0].tasks[0]", "ansible.builtin.apt", "Install nginx", 3, 5},
		{"site.yml|plays[0].tasks[1].block[0]", "ansible.builtin.service", "Start nginx", 7, 9},
		{"site.yml|plays[0].handlers[0]", "ansible.builtin.service", "restart nginx", 11, 14},
		{"site.yml|plays[1].tasks[0]", "ansible.builtin.ping", "ansible.builtin.ping", 17, 17},
		{"roles/web/tasks/main.yml|tasks[0]", "ansible.builtin.copy", "Copy config", 1, 4},
		// The module an action or local_action names, not the keyword.
		{"roles/web/tasks/main.yml|tasks[1]", "ansible.builtin.copy", "Copy by action", 5, 6},
		{"roles/web/tasks/main.yml|tasks[2]", "ansible.builtin.command", "Echo locally", 7, 8},
		{"roles/web/tasks/main.yml|tasks[3]", "ansible.builtin.copy", "Copy by mapping", 9, 12},
		{"roles/web/tasks/main.yml|tasks[4]", "shell", "Escalate", 13, 15},
		{"roles/web/tasks/main.yml|tasks[5]", "ansible.builtin.shell", "Escalate fully", 16, 18},
	} {
		require.Equal(t, w, got[w.ref], w.ref)
	}
	require.Len(t, inv.Resources, 21)
	require.Contains(t, inv.Files, inventory.File{Path: "data/cities.yml", Platform: "ansible", Status: inventory.FileScanned},
		"the list is scanned as Ansible, yet gives no row")
	for _, r := range inv.Resources {
		if r.Platform == platforms.CloudFormation {
			require.Equal(t, "aws", r.Provider)
		}
	}
}

func TestInventoryGitLabDeclaredJobs(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".gitlab-ci.yml":          "include: missing.yml\n.base: {script: echo base}\nbuild: {extends: .base}\nid: {script: echo id}\nfile: {script: echo file}\n_dd_lines: {}\n",
		"ci/.gitlab-ci.yaml":      "deploy: {trigger: other/project}\n",
		".gitlab/ci/fragment.yml": "fragment: {script: echo fragment}\n",
		"pipeline.yml":            "custom: {script: echo custom}\n",
	})
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprint(explicit), func(t *testing.T) {
			params := documentParams(root)
			params.Platform = []string{"CICD"}
			if explicit {
				params.Path = []string{filepath.Join(root, ".gitlab-ci.yml"), filepath.Join(root, "ci/.gitlab-ci.yaml")}
			}
			inv := scanInventory(t, params)
			require.Len(t, inv.Resources, 5)
			for _, row := range inv.Resources {
				require.Equal(t, "gitlab_ci_job", row.ResourceType)
				require.Equal(t, "cicd", row.Platform)
				require.Greater(t, row.LineStart, 0)
				require.Equal(t, row.LineStart, row.LineEnd)
			}
		})
	}
}
