package analyzer

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/platforms"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
)

func Test_yamlRootHasAnyKey(t *testing.T) {
	tests := []struct {
		name    string
		content string
		keys    []string
		want    bool
	}{
		{
			name:    "root play list",
			content: "- name: demo\n  hosts: localhost\n",
			keys:    []string{"playbooks"},
			want:    true,
		},
		{
			name:    "root playbooks key",
			content: "playbooks:\n  - hosts: all\n",
			keys:    []string{"playbooks"},
			want:    true,
		},
		{
			name:    "plain root key padded before colon",
			content: "resources : []\n",
			keys:    []string{"resources"},
			want:    true,
		},
		{
			name:    "plain root key with tab before colon",
			content: "all\t:\n  hosts: {}\n",
			keys:    []string{"all"},
			want:    true,
		},
		{
			name:    "plain root key prefix does not match",
			content: "resourcesExtra: []\n",
			keys:    []string{"resources"},
			want:    false,
		},
		{
			name:    "indented root",
			content: "  resources: []\n",
			keys:    []string{"resources"},
			want:    true,
		},
		{
			name:    "nested matching key",
			content: "metadata:\n  resources:\n    - name: x\n",
			keys:    []string{"resources"},
			want:    false,
		},
		{
			name:    "comment and document marker",
			content: "---\n# note\nresources:\n  - name: x\n",
			keys:    []string{"resources"},
			want:    true,
		},
		{
			name:    "flow mapping root",
			content: "{resources: []}\n",
			keys:    []string{"resources"},
			want:    true,
		},
		{
			name:    "flow sequence root",
			content: "[{hosts: all}]\n",
			keys:    []string{"playbooks"},
			want:    true,
		},
		{
			name:    "flow root after document marker",
			content: "--- {resources: []}\n",
			keys:    []string{"resources"},
			want:    true,
		},
		{
			name:    "root merge key",
			content: "defaults: &defaults\n  resources: []\n<<: *defaults\n",
			keys:    []string{"resources"},
			want:    true,
		},
		{
			name:    "quoted root key",
			content: `"resources": []` + "\n",
			keys:    []string{"resources"},
			want:    true,
		},
		{
			name:    "single quoted root key",
			content: "'all':\n  hosts: {}\n",
			keys:    []string{"all"},
			want:    true,
		},
		{
			name:    "quoted root key padded before colon",
			content: `"resources" : []` + "\n",
			keys:    []string{"resources"},
			want:    true,
		},
		{
			name:    "quoted root key that does not match",
			content: `"metadata": {}` + "\n",
			keys:    []string{"resources"},
			want:    false,
		},
		{
			name:    "quoted root scalar is not a key",
			content: `"resources"` + "\n",
			keys:    []string{"resources"},
			want:    false,
		},
		{
			name:    "escaped quote is left for the parser",
			content: `"res\"ources": []` + "\n",
			keys:    []string{"resources"},
			want:    true,
		},
		{
			name:    "go template root is not a flow mapping",
			content: "{{ .Rule.Name }}-publish:\n  stage: publish\n",
			keys:    []string{"resources"},
			want:    false,
		},
		{
			name:    "helm template root is not a flow mapping",
			content: "{{- if .Values.enabled }}\nmetadata:\n  name: demo\n",
			keys:    []string{"resources"},
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, yamlRootHasAnyKey([]byte(tt.content), tt.keys...))
		})
	}
}

func Test_checkYamlPlatform_playbookSequenceRoot(t *testing.T) {
	ctx := context.Background()
	content := []byte(`---
- name: Configure web servers
  hosts: web_servers
  roles:
    - common
`)
	require.Equal(t, ansible, checkYamlPlatform(ctx, nil, content, "playbook.yml", nil))
}

func Test_checkYamlPlatform_ansibleWithoutFullDocumentUnmarshal(t *testing.T) {
	ctx := context.Background()
	content := []byte(`playbooks:
  - name: demo
    hosts: localhost
    tasks:
      - debug: msg=hi
`)
	require.Equal(t, ansible, checkYamlPlatform(ctx, nil, content, "site.yml", nil))
}

func Test_checkYamlPlatform_ansibleInventoryMergeAlias(t *testing.T) {
	ctx := context.Background()
	content := []byte(`inventory: &inventory
  hosts:
    web: {}
all:
  <<: *inventory
`)
	require.Equal(t, ansible, checkYamlPlatform(ctx, nil, content, "inventory.yml", nil))
}

func Test_checkYamlPlatform_aliasBackedInventory(t *testing.T) {
	ctx := context.Background()
	content := []byte(`inventory: &inventory
  hosts:
    web: {}
all: *inventory
`)
	require.Equal(t, ansible, checkYamlPlatform(ctx, nil, content, "inventory.yml", nil))
}

func Test_checkYamlPlatform_aliasBackedPlaybooks(t *testing.T) {
	ctx := context.Background()
	content := []byte(`plays: &plays
  - hosts: all
playbooks: *plays
`)
	require.Equal(t, ansible, checkYamlPlatform(ctx, nil, content, "playbook.yaml", nil))
}

func Test_checkYamlPlatform_quotedRootKeys(t *testing.T) {
	ctx := context.Background()
	require.Equal(t, gdm, checkYamlPlatform(ctx, nil, []byte(`"resources": []`), "deployment.yaml", nil))
	require.Equal(t, ansible, checkYamlPlatform(ctx, nil, []byte(`'all':
  hosts:
    web: {}
`), "inventory.yaml", nil))
}

func Test_checkYamlPlatform_flowStyleRoots(t *testing.T) {
	ctx := context.Background()
	require.Equal(t, gdm, checkYamlPlatform(ctx, nil, []byte(`{resources: []}`), "deployment.yaml", nil))
	require.Equal(t, ansible, checkYamlPlatform(ctx, nil, []byte(`[{hosts: all}]`), "playbook.yaml", nil))
}

func Test_checkYamlPlatform_rootMerge(t *testing.T) {
	content := []byte(`defaults: &defaults
  resources: []
<<: *defaults
`)
	require.Equal(t, gdm, checkYamlPlatform(context.Background(), nil, content, "deployment.yaml", nil))
}

func Test_checkYamlPlatform_indentedRoots(t *testing.T) {
	ctx := context.Background()
	require.Equal(t, gdm, checkYamlPlatform(ctx, nil, []byte(`  resources: []`), "deployment.yaml", nil))
	require.Equal(t, ansible, checkYamlPlatform(ctx, nil, []byte(`  playbooks:
    - hosts: all
`), "playbook.yaml", nil))
}

func Test_checkYamlPlatform_encryptedGroupVars(t *testing.T) {
	content := []byte("$ANSIBLE_VAULT;1.1;AES256\ninvalid\n")
	require.Equal(t, "", checkYamlPlatform(context.Background(), nil, content, "ansible/group_vars/all/vault.yml", nil))
}

func Test_checkYamlPlatform_pathVarsRequireMappingRoot(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{name: "mapping", content: "region: us-east-1\n", want: ansible},
		{name: "empty", content: "", want: ""},
		{name: "comment only", content: "---\n# vars\n", want: ""},
		{name: "scalar", content: "value\n", want: ""},
		{name: "sequence", content: "- value\n", want: ""},
		{name: "malformed", content: "key: [\n", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkYamlPlatform(
				context.Background(),
				nil,
				[]byte(tt.content),
				"ansible/group_vars/all/main.yml",
				nil,
			)
			require.Equal(t, tt.want, got)
		})
	}
}

func Test_checkYamlPlatform_skipsParseWhenNoRootKeys(t *testing.T) {
	ctx := context.Background()
	content := []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: demo
`)
	require.Equal(t, "", checkYamlPlatform(ctx, nil, content, "manifest.yaml", nil))
}

func Test_checkYamlPlatform_dockerCompose(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		content   string
		typesFlag []string
		// files populates the FS the classifier sees; used for the override
		// guard's sibling-base check.
		files map[string][]byte
		want  string
	}{
		{
			name: "versionless image service",
			path: "stack.yaml",
			content: `services:
  web:
    image: nginx:latest
`,
			want: dockercompose,
		},
		{
			name: "build service",
			path: "compose.yml",
			content: `services:
  api:
    build:
      context: .
`,
			want: dockercompose,
		},
		{
			name: "override file with base sibling not classified standalone",
			path: "compose.override.yaml",
			content: `services:
  worker:
    extends:
      file: compose.yaml
      service: base
`,
			files: map[string][]byte{"compose.yaml": []byte("services: {}\n")},
			want:  "",
		},
		{
			name: "override file without base scans standalone",
			path: "compose.override.yaml",
			content: `services:
  web:
    image: nginx:1.27
`,
			want: dockercompose,
		},
		{
			name: "override with base not classified even with explicit selection",
			path: "docker-compose.override.yml",
			content: `services:
  web:
    ports:
      - "8080:80"
`,
			typesFlag: []string{"dockercompose"},
			files:     map[string][]byte{"docker-compose.yml": []byte("services: {}\n")},
			want:      "",
		},
		{
			name: "explicit selection accepts non canonical override",
			path: "prod.yaml",
			content: `services:
  web:
    ports:
      - "8080:80"
    environment:
      APP_ENV: production
`,
			typesFlag: []string{"dockercompose"},
			want:      dockercompose,
		},
		{
			name: "default supported types keep strict override matching",
			path: "prod.yaml",
			content: `services:
  web:
    ports:
      - "8080:80"
    environment:
      APP_ENV: production
`,
			typesFlag: platforms.Supported,
		},
		{
			name: "generic services mapping",
			path: "application.yaml",
			content: `services:
  billing:
    endpoint: https://example.test
`,
			typesFlag: platforms.Supported,
		},
		{
			name: "nested services mapping",
			path: "application.yaml",
			content: `application:
  services:
    web:
      image: nginx
`,
		},
		{
			name: "services must be a mapping",
			path: "compose.yaml",
			content: `services:
  - web
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, checkYamlPlatform(
				context.Background(),
				vfs.NewMemFS(tt.files),
				[]byte(tt.content),
				tt.path,
				tt.typesFlag,
			))
		})
	}
}

func Test_isYamlTemplatePath(t *testing.T) {
	require.True(t, isYamlTemplatePath("domains/foo/ci.tpl.yaml"))
	require.True(t, isYamlTemplatePath("domains/foo/ci.tpl.yml"))
	require.True(t, isYamlTemplatePath("domains/foo/ephemera-kind-e2e-tpl.yaml"))
	require.False(t, isYamlTemplatePath("domains/foo/pipeline.yaml"))
}

func Test_yamlHasRootTemplateSyntax(t *testing.T) {
	require.True(t, yamlHasRootTemplateSyntax([]byte("stages:\n  - test\n\n{{ .Rule.Name }}-job:\n  script: echo hi\n")))
	require.True(t, yamlHasRootTemplateSyntax([]byte("{{- if .Values.enabled }}\nmetadata:\n  name: demo\n")))
	require.False(t, yamlHasRootTemplateSyntax([]byte("stages:\n  - test\njob:\n  script: echo hi\n")))
	require.False(t, yamlHasRootTemplateSyntax([]byte("stages:\n  - test\n  {{ .Nested }}: value\n")))
}

func Test_checkYamlPlatform_skipsUnrenderedTemplates(t *testing.T) {
	ctx := context.Background()

	gitlabCI := []byte(`stages:
  - publish

{{ .Rule.Name }}-publish:
  stage: publish
  script:
    - bzl run //domains/foo:target
`)
	require.Equal(t, "", checkYamlPlatform(ctx, nil, gitlabCI, "domains/foo/pipeline.yaml", nil))

	helmFabric := []byte(`{{- if .Values.fabric.egress.enabled }}
metadata:
  name: demo
spec:
  rules: []
`)
	require.Equal(t, "", checkYamlPlatform(ctx, nil, helmFabric, "domains/foo/config/k8s/fabric/egress-acl.yaml", nil))
}

func Test_checkYamlPlatform_parseableTplYamlStillClassified(t *testing.T) {
	content := []byte(`- name: demo
  hosts: "{{ target_hosts }}"
  tasks:
    - debug: msg=hi
`)
	require.Equal(t, ansible, checkYamlPlatform(context.Background(), nil, content, "playbooks/site.tpl.yaml", nil))
}
