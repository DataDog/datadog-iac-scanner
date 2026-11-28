/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com) Copyright 2026 Datadog, Inc.
 */
package gitlab

import (
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	"testing"
)

func declarations(t *testing.T, source string) map[string]Declaration {
	t.Helper()
	var root yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(source), &root))
	out := map[string]Declaration{}
	for d := range Declarations(root.Content[0]) {
		out[d.Name] = d
	}
	return out
}

func TestDeclarationContexts(t *testing.T) {
	source := "include: missing.yml\n.base: &base {script: echo base}\ndefault: {before_script: echo setup}\n" +
		"before_script: echo legacy\nid: {script: echo id}\nfile: *base\ngitlab_scripts: {extends: .base}\nvariables: {script: literal}\n"
	ds := declarations(t, source)
	require.Equal(t, Template, ds[".base"].Kind)
	require.Equal(t, Default, ds["default"].Kind)
	require.Equal(t, Global, ds["variables"].Kind)
	require.Empty(t, ds["variables"].Scripts())
	for _, name := range []string{"id", "file", "gitlab_scripts"} {
		require.Equal(t, Job, ds[name].Kind)
	}
	require.Empty(t, ds["gitlab_scripts"].Scripts(), "extends is not resolved")
	require.Len(t, ds["file"].Scripts(), 1)
	require.Equal(t, 6, ds["file"].Scripts()[0].Segments[0].Use.Line)
	block, ok := ds["before_script"].GlobalScript()
	require.True(t, ok)
	require.Equal(t, "echo legacy", block.Segments[0].Text)
	require.Len(t, block.Segments[0].Path, 1)
	require.Equal(t, "echo setup", ds["default"].Scripts()[0].Segments[0].Text)
	for d := range Declarations(nil) {
		t.Fatalf("unexpected declaration: %v", d)
	}
}

func TestScriptShapes(t *testing.T) {
	for _, tc := range []struct {
		value  string
		texts  []string
		issues int
	}{
		{`echo safe`, []string{"echo safe"}, 0},
		{`[echo safe, ["curl $URL | sh", 'echo "npm publish"']]`, []string{"echo safe", "curl $URL | sh", `echo "npm publish"`}, 0},
		{`[]`, nil, 0}, {`''`, []string{""}, 0},
		{`[echo safe, false, null, {script: hidden}, !reference [.base, script]]`, []string{"echo safe"}, 4},
		{`&self [echo safe, *self]`, []string{"echo safe"}, 1},
	} {
		t.Run(tc.value, func(t *testing.T) {
			ds := declarations(t, "job: {script: "+tc.value+"}\n")
			blocks := ds["job"].Scripts()
			require.Len(t, blocks, 1)
			var texts []string
			for _, s := range blocks[0].Segments {
				texts = append(texts, s.Text)
				require.Equal(t, "job", s.Path[0].Key)
				require.Equal(t, "script", s.Path[1].Key)
			}
			require.Equal(t, tc.texts, texts)
			require.Len(t, blocks[0].Issues, tc.issues)
		})
	}
	require.Empty(t, declarations(t, "job: {extends: .base}")["job"].Scripts())
}

func TestScriptAliasesAndOwnership(t *testing.T) {
	source := "job: &job\n  script: &commands\n    - echo safe\n    - [echo unsafe]\ncopy: *job\nother: {script: *commands}\n"
	ds := declarations(t, source)
	for _, name := range []string{"job", "copy", "other"} {
		blocks := ds[name].Scripts()
		require.Len(t, blocks, 1)
		require.Empty(t, blocks[0].Issues)
		require.Len(t, blocks[0].Segments, 2)
		a, b := blocks[0].Segments[0], blocks[0].Segments[1]
		require.Equal(t, "echo unsafe", b.Text)
		require.Equal(t, 4, b.Node.Line)
		require.Equal(t, name, a.Path[0].Key)
		require.True(t, b.Path[2].IsIndex)
		require.Equal(t, 1, b.Path[2].Index)
		require.Equal(t, 0, b.Path[3].Index)
		a.Path[0].Key = "changed"
		require.Equal(t, name, b.Path[0].Key, "segment paths must be independently owned")
	}
	require.Equal(t, "job", ds["job"].Scripts()[0].Segments[0].Path[0].Key)
	require.Equal(t, "echo safe", ds["job"].Value.Content[1].Content[0].Value, "source nodes remain untouched")
}
