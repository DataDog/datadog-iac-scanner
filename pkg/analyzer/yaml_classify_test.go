package analyzer

import (
	"context"
	"testing"

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
	require.Equal(t, ansible, checkYamlPlatform(ctx, content, "playbook.yml"))
}

func Test_checkYamlPlatform_ansibleWithoutFullDocumentUnmarshal(t *testing.T) {
	ctx := context.Background()
	content := []byte(`playbooks:
  - name: demo
    hosts: localhost
    tasks:
      - debug: msg=hi
`)
	require.Equal(t, ansible, checkYamlPlatform(ctx, content, "site.yml"))
}

func Test_checkYamlPlatform_ansibleInventoryMergeAlias(t *testing.T) {
	ctx := context.Background()
	content := []byte(`inventory: &inventory
  hosts:
    web: {}
all:
  <<: *inventory
`)
	require.Equal(t, ansible, checkYamlPlatform(ctx, content, "inventory.yml"))
}

func Test_checkYamlPlatform_aliasBackedInventory(t *testing.T) {
	ctx := context.Background()
	content := []byte(`inventory: &inventory
  hosts:
    web: {}
all: *inventory
`)
	require.Equal(t, ansible, checkYamlPlatform(ctx, content, "inventory.yml"))
}

func Test_checkYamlPlatform_aliasBackedPlaybooks(t *testing.T) {
	ctx := context.Background()
	content := []byte(`plays: &plays
  - hosts: all
playbooks: *plays
`)
	require.Equal(t, ansible, checkYamlPlatform(ctx, content, "playbook.yaml"))
}

func Test_checkYamlPlatform_quotedRootKeys(t *testing.T) {
	ctx := context.Background()
	require.Equal(t, gdm, checkYamlPlatform(ctx, []byte(`"resources": []`), "deployment.yaml"))
	require.Equal(t, ansible, checkYamlPlatform(ctx, []byte(`'all':
  hosts:
    web: {}
`), "inventory.yaml"))
}

func Test_checkYamlPlatform_flowStyleRoots(t *testing.T) {
	ctx := context.Background()
	require.Equal(t, gdm, checkYamlPlatform(ctx, []byte(`{resources: []}`), "deployment.yaml"))
	require.Equal(t, ansible, checkYamlPlatform(ctx, []byte(`[{hosts: all}]`), "playbook.yaml"))
}

func Test_checkYamlPlatform_rootMerge(t *testing.T) {
	content := []byte(`defaults: &defaults
  resources: []
<<: *defaults
`)
	require.Equal(t, gdm, checkYamlPlatform(context.Background(), content, "deployment.yaml"))
}

func Test_checkYamlPlatform_indentedRoots(t *testing.T) {
	ctx := context.Background()
	require.Equal(t, gdm, checkYamlPlatform(ctx, []byte(`  resources: []`), "deployment.yaml"))
	require.Equal(t, ansible, checkYamlPlatform(ctx, []byte(`  playbooks:
    - hosts: all
`), "playbook.yaml"))
}

func Test_checkYamlPlatform_encryptedGroupVars(t *testing.T) {
	content := []byte("$ANSIBLE_VAULT;1.1;AES256\ninvalid\n")
	require.Equal(t, "", checkYamlPlatform(context.Background(), content, "ansible/group_vars/all/vault.yml"))
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
				[]byte(tt.content),
				"ansible/group_vars/all/main.yml",
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
	require.Equal(t, "", checkYamlPlatform(ctx, content, "manifest.yaml"))
}
