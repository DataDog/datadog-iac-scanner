/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/hclcache"
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

	cache := hclcache.New()
	ctx := hclcache.WithCache(context.Background(), cache)
	e := New()
	e.SetHCLCache(cache)
	first, _, _, err := e.EvaluateModule(ctx, stack, nil)
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
	if got := cache.Stats().Entries; got != 2 {
		t.Fatalf("hclcache entries after evaluation = %d, want 2", got)
	}

	e.ForgetRootParse(stack)
	if got := cached(); !reflect.DeepEqual(got, []string{"bucket"}) {
		t.Fatalf("parse cache after forgetting the root = %v, want only the called module", got)
	}
	if got := cache.Stats().Entries; got != 1 {
		t.Fatalf("hclcache entries after forgetting the root = %d, want 1 (called module only)", got)
	}

	e.ReleaseEvalCache()
	again, _, _, err := e.EvaluateModule(ctx, stack, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != len(first) || again[0].Attributes["bucket"].AsString() != "logs" {
		t.Fatalf("re-evaluating a forgotten root = %+v, want %+v", again, first)
	}
}
