/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"io/fs"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
)

func TestForgetRootParseKeepsCalledModules(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "modules/bucket", map[string]string{
		"main.tf": `
variable "name" {}
resource "aws_s3_bucket" "b" { bucket = var.name }
`,
	})
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
module "bucket" {
  source = "../modules/bucket"
  name   = "logs"
}
`,
	})

	e := New()
	evaluation, err := e.EvaluateModule(context.Background(), stack, nil)
	first := evaluation.Resources
	if err != nil {
		t.Fatal(err)
	}
	cached := func() []string {
		e.parseMu.Lock()
		defer e.parseMu.Unlock()
		var dirs []string
		for key := range e.dirCache {
			dirs = append(dirs, filepath.Base(strings.SplitN(key, "\x00", 2)[0]))
		}
		return dirs
	}
	if got := cached(); len(got) != 2 {
		t.Fatalf("parse cache after evaluation = %v, want the root and the module it calls", got)
	}

	e.ForgetRootParse(stack)
	if got := cached(); !reflect.DeepEqual(got, []string{"bucket"}) {
		t.Fatalf("parse cache after forgetting the root = %v, want only the called module", got)
	}

	e.ReleaseEvalCache()
	evaluation2, err := e.EvaluateModule(context.Background(), stack, nil)
	again := evaluation2.Resources
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != len(first) || again[0].Attributes["bucket"].AsString() != "logs" {
		t.Fatalf("re-evaluating a forgotten root = %+v, want %+v", again, first)
	}
}

// Configuration failures belong to the module occurrence, even if no resource
// survives parsing. Valid files retain their values and cached failures retain
// their attribution when the same directory is called at another address.
func TestModuleConfigurationParsing(t *testing.T) {
	for _, test := range []struct {
		name       string
		files      map[string]string
		unreadable string
		failed     bool
		resources  int
	}{
		{"known HCL", map[string]string{"main.tf": `resource "test_resource" "known" {value="known"}`}, "", false, 1},
		{"known JSON", map[string]string{"main.tf.json": `{"resource":{"test_resource":{"known":{"value":"known"}}}}`}, "", false, 1},
		{"invalid HCL", map[string]string{"bad.tf": `resource "test_resource" "broken" {`}, "", true, 0},
		{"invalid JSON", map[string]string{"bad.tf.json": `{"resource":`}, "", true, 0},
		{"mixed files", map[string]string{"bad.tf": `resource "test_resource" "broken" {`, "main.tf": `resource "test_resource" "known" {value="known"}`}, "", true, 1},
		{"JSON interpolation syntax", map[string]string{"bad.tf.json": `{"resource":{"test_resource":{"broken":{"value":"${foo(}"}}}}`}, "", true, 1},
		{"JSON block structure", map[string]string{"bad.tf.json": `{"resource":[]}`}, "", true, 0},
		{"read failure", map[string]string{"bad.tf": `resource "test_resource" "hidden" {}`, "main.tf": `resource "test_resource" "known" {value="known"}`}, "bad.tf", true, 1},
		{"shadowed invalid twin", map[string]string{"main.tf": `invalid {`, "main.tofu": `resource "test_resource" "known" {value="known"}`}, "", false, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			module := writeModule(t, root, "child", test.files)
			caller := writeModule(t, root, "caller", map[string]string{"main.tf": `module "left" {source="../child"}
module "right" {source="../child"}`})
			fsys := &configurationReadFS{FS: vfs.DiskFS{}}
			if test.unreadable != "" {
				fsys.failPath = filepath.Join(module, test.unreadable)
			}
			e := NewWithFS(fsys)
			// Direct root, then two occurrences sharing the completed module cache.
			for _, invocation := range []struct {
				dir    string
				copies int
			}{{module, 1}, {caller, 2}, {caller, 2}} {
				result, err := e.EvaluateModule(context.Background(), invocation.dir, nil)
				require.NoError(t, err)
				require.Len(t, result.Resources, invocation.copies*test.resources)
				diagnostics := result.Diagnostics()
				if !test.failed {
					require.Empty(t, diagnostics)
					continue
				}
				require.NotEmpty(t, diagnostics)
				addresses := map[string]bool{}
				for _, diagnostic := range diagnostics {
					file := "bad.tf"
					if _, exists := test.files["bad.tf.json"]; exists {
						file = "bad.tf.json"
					}
					require.Equal(t, filepath.Join(module, file), diagnostic.Subject.Filename)
					require.NotEmpty(t, diagnostic.Summary)
					require.NotEmpty(t, diagnostic.Detail)
					addresses[diagnostic.ModuleAddress] = true
				}
				if invocation.copies == 1 {
					require.Equal(t, map[string]bool{"": true}, addresses)
				} else {
					require.Equal(t, map[string]bool{"module.left": true, "module.right": true}, addresses)
				}
				// Inspection cannot mutate the parse-cache facts or the policy failure.
				diagnostics[0].Summary = "modified inspection"
				var diagnostic *EvaluationDiagnostic
				require.ErrorAs(t, result.PolicyUnit(nil).Failure(), &diagnostic)
				require.NotEqual(t, "modified inspection", diagnostic.Summary)
			}
			result, err := e.EvaluateModule(context.Background(), module, nil)
			require.NoError(t, err)
			for _, resource := range result.Resources {
				if resource.Name == "known" {
					requireString(t, resource.Attributes, "value", "known")
				}
			}
		})
	}
}

func TestModuleConfigurationParseCancellation(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "module", map[string]string{
		"first.tf":  `resource "test_resource" "one" {}`,
		"second.tf": `resource "test_resource" "two" {}`,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fsys := &configurationReadFS{FS: vfs.DiskFS{}, cancel: cancel}
	e := NewWithFS(fsys)
	// Discovery shares this cache with evaluation. A canceled read cannot
	// publish a partial parsed directory for a later successful invocation.
	require.ErrorIs(t, e.parseDir(ctx, dir, "").err, context.Canceled)
	fsys.cancel = nil
	result, err := e.EvaluateModule(context.Background(), dir, nil)
	require.NoError(t, err)
	require.Len(t, result.Resources, 2)
	require.Empty(t, result.Diagnostics())
}

type configurationReadFS struct {
	vfs.FS
	failPath string
	cancel   context.CancelFunc
}

func (f *configurationReadFS) ReadFile(path string) ([]byte, error) {
	if f.cancel != nil {
		f.cancel()
	}
	if path == f.failPath {
		return nil, fs.ErrPermission
	}
	return f.FS.ReadFile(path)
}
