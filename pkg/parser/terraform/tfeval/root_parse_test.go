/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"errors"
	"io/fs"
	"os"
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

func TestModuleConfigurationOverrideLoading(t *testing.T) {
	for _, test := range []struct {
		name       string
		files      map[string]string
		unreadable string
		failed     bool
	}{
		{"ordinary invalid file", map[string]string{"bad.tf": `resource "test_resource" "broken" {`}, "", false},
		{"HCL override syntax", map[string]string{"bad_override.tf": `resource "test_resource" "item" {acl="private"`}, "", true},
		{"JSON override syntax", map[string]string{"bad_override.tf.json": `{"resource":`}, "", true},
		{"HCL override read", map[string]string{"bad_override.tf": ``}, "bad_override.tf", true},
		{"JSON override read", map[string]string{"bad_override.tf.json": `{}`}, "bad_override.tf.json", true},
		{"shadowed invalid Terraform twin", map[string]string{"dialect_override.tf": `invalid {`, "dialect_override.tofu": ``}, "", false},
		{"selected invalid OpenTofu twin", map[string]string{"dialect_override.tf": ``, "dialect_override.tofu": `invalid {`}, "", true},
		{"already loaded zero expansion", map[string]string{"main.tf": `resource "test_resource" "item" {count=0}`, "bad_override.tf": `invalid {`}, "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			files := map[string]string{"main.tf": `resource "test_resource" "item" {acl="public"}`}
			for file, source := range test.files {
				files[file] = source
			}
			dir := writeModule(t, t.TempDir(), "module", files)
			e := New()
			if test.unreadable != "" {
				e = NewWithFS(&configurationReadFS{FS: vfs.DiskFS{}, failPath: filepath.Join(dir, test.unreadable)})
			}
			for i := 0; i < 2; i++ {
				result, err := e.EvaluateModule(context.Background(), dir, nil)
				if !test.failed {
					require.NoError(t, err)
					require.Len(t, result.Resources, 1)
					requireString(t, result.Resources[0].Attributes, "acl", "public")
					continue
				}
				require.Error(t, err)
				require.Empty(t, result.Resources)
				require.Empty(t, result.Outputs)
				var configuration *ConfigurationError
				require.ErrorAs(t, result.Failure(), &configuration)
				require.False(t, result.InventoryObservations().EvaluationCompleted)
				var diagnostic *EvaluationDiagnostic
				require.ErrorAs(t, err, &diagnostic)
				require.True(t, strings.Contains(diagnostic.Subject.Filename, "override."))
				require.Greater(t, diagnostic.Subject.Start.Line, 0)
				original := diagnostic.Subject
				diagnostic.Subject.Filename = "changed error inspection"
				var again *EvaluationDiagnostic
				require.ErrorAs(t, err, &again)
				require.Equal(t, original, again.Subject)
				var unitDiagnostic *EvaluationDiagnostic
				require.ErrorAs(t, result.PolicyUnit(nil).Failure(), &unitDiagnostic)
				require.Equal(t, original, unitDiagnostic.Subject)
			}
		})
	}
	t.Run("unavailable confined override", func(t *testing.T) {
		outside := writeModule(t, t.TempDir(), "outside", map[string]string{"config.tf": ``})
		dir := writeModule(t, t.TempDir(), "module", map[string]string{"main.tf": `resource "test_resource" "item" {acl="public"}`})
		require.NoError(t, os.Symlink(filepath.Join(outside, "config.tf"), filepath.Join(dir, "confined_override.tf")))
		result, err := New().EvaluateModule(context.Background(), dir, nil)
		require.Error(t, err)
		require.Empty(t, result.Resources)
		var diagnostic *EvaluationDiagnostic
		require.ErrorAs(t, err, &diagnostic)
		require.Equal(t, filepath.Join(dir, "confined_override.tf"), diagnostic.Subject.Filename)
	})
}

func TestModuleConfigurationOverrideContexts(t *testing.T) {
	root := t.TempDir()
	child := writeModule(t, root, "child", map[string]string{"main.tf": `output "acl" {value="public"}`, "bad_override.tf": `output "acl" {value="private"`})
	caller := writeModule(t, root, "caller", map[string]string{"main.tf": `module "left" {source="../child"}
module "right" {source="../child"}
resource "test_resource" "independent" {acl="public"}
resource "test_resource" "dependent" {acl=module.left.acl}`})
	e := New()
	for i := 0; i < 2; i++ {
		result, err := e.EvaluateModule(context.Background(), caller, nil)
		require.NoError(t, err)
		require.Len(t, result.Resources, 2)
		requireString(t, findResource(t, result.Resources, "test_resource", "independent").Attributes, "acl", "public")
		requireUnknown(t, findResource(t, result.Resources, "test_resource", "dependent").Attributes, "acl")
		var configuration *ConfigurationError
		require.ErrorAs(t, result.Failure(), &configuration)
		require.Len(t, configuration.Unwrap(), 2)
		originalFailure := result.Failure().Error()
		for _, cause := range configuration.Unwrap() {
			var diagnostic *EvaluationDiagnostic
			require.ErrorAs(t, cause, &diagnostic)
			diagnostic.Subject.Filename = "mutated detached failure"
		}
		require.Equal(t, originalFailure, result.Failure().Error())
		diagnostics := result.Diagnostics()
		require.Len(t, diagnostics, 2)
		require.Equal(t, []string{"module.left", "module.right"}, []string{diagnostics[0].ModuleAddress, diagnostics[1].ModuleAddress})
		for _, diagnostic := range diagnostics {
			require.Equal(t, filepath.Join(child, "bad_override.tf"), diagnostic.Subject.Filename)
		}
	}
	// A runtime-zero call whose source was never loaded is not a certificate
	// that the child configuration was parsed or validated. Do not add I/O here.
	zero := writeModule(t, root, "zero", map[string]string{"main.tf": `module "child" {
source="../child"
count=0
}`})
	result, err := e.EvaluateModule(context.Background(), zero, nil)
	require.NoError(t, err)
	require.True(t, result.InventoryObservations().EvaluationCompleted)
	require.Empty(t, result.Resources)
	// The root error keeps every original parse failure through standard unwrap.
	mixed := writeModule(t, root, "mixed", map[string]string{"bad.tf": `bad {`, "bad_override.tf": `bad {`})
	_, err = e.EvaluateModule(context.Background(), mixed, nil)
	require.Error(t, err)
	var failure *ConfigurationError
	require.ErrorAs(t, err, &failure)
	sources := map[string]bool{}
	for _, cause := range failure.Unwrap() {
		var diagnostic *EvaluationDiagnostic
		require.True(t, errors.As(cause, &diagnostic))
		sources[filepath.Base(diagnostic.Subject.Filename)] = true
	}
	require.Equal(t, map[string]bool{"bad.tf": true, "bad_override.tf": true}, sources)
}
