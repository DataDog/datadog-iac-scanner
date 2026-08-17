package analyzer

import (
	"context"
	"path/filepath"
	"sync"
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
			name:    "indented only",
			content: "  hosts: all\n",
			keys:    []string{"playbooks", "all"},
			want:    false,
		},
		{
			name:    "comment and document marker",
			content: "---\n# note\nresources:\n  - name: x\n",
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

func Test_checkYamlPlatform_skipsParseWhenNoRootKeys(t *testing.T) {
	ctx := context.Background()
	content := []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: demo
`)
	require.Equal(t, "", checkYamlPlatform(ctx, content, "manifest.yaml"))
}

func Test_checkHelm_cachesByStartDirectory(t *testing.T) {
	helm := filepath.FromSlash("../../test/fixtures/analyzer_test/helm")
	cache := &sync.Map{}
	path := filepath.Join(helm, "templates", "service.yaml")

	require.True(t, checkHelm(context.Background(), path, cache))
	_, loaded := cache.Load(filepath.Dir(path))
	require.True(t, loaded)
}
