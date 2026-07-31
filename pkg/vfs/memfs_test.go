/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package vfs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func newTestMemFS() *MemFS {
	return NewMemFS(map[string][]byte{
		"infra/main.tf":             []byte(`resource "aws_s3_bucket" "b" {}`),
		"infra/variables.tf":        []byte(`variable "name" {}`),
		"infra/prod.auto.tfvars":    []byte(`name = "prod"`),
		"infra/modules/net/main.tf": []byte(`resource "x" "y" {}`),
		"./root.tf":                 []byte(`# root`),
	})
}

func TestMemFS_ReadFile(t *testing.T) {
	m := newTestMemFS()

	got, err := m.ReadFile("infra/main.tf")
	if err != nil {
		t.Fatalf("ReadFile hit: unexpected error %v", err)
	}
	if string(got) != `resource "aws_s3_bucket" "b" {}` {
		t.Errorf("ReadFile content = %q", got)
	}

	// Normalization: a dot-prefixed push is reachable by its clean key.
	if _, err := m.ReadFile("root.tf"); err != nil {
		t.Errorf("ReadFile normalized key: unexpected error %v", err)
	}

	// Miss is recorded and reports fs.ErrNotExist.
	if _, err := m.ReadFile("infra/absent.tf"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ReadFile miss err = %v, want ErrNotExist", err)
	}
	if got := m.MissingFiles(); !reflect.DeepEqual(got, []string{"infra/absent.tf"}) {
		t.Errorf("MissingFiles after ReadFile miss = %v", got)
	}
}

func TestMemFS_StatDoesNotRecordMiss(t *testing.T) {
	m := newTestMemFS()

	if _, err := m.Stat("infra/main.tf"); err != nil {
		t.Errorf("Stat hit: unexpected error %v", err)
	}
	// terraform.tfvars is a speculative probe; a miss must NOT be recorded.
	if _, err := m.Stat("infra/terraform.tfvars"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Stat miss err = %v, want ErrNotExist", err)
	}
	if got := m.MissingFiles(); len(got) != 0 {
		t.Errorf("Stat miss must not be recorded, got MissingFiles = %v", got)
	}
}

func TestMemFS_Glob(t *testing.T) {
	m := newTestMemFS()

	tf, err := m.Glob(filepath.Join("infra", "*.tf"))
	if err != nil {
		t.Fatalf("Glob *.tf: %v", err)
	}
	want := []string{"infra/main.tf", "infra/variables.tf"}
	if !reflect.DeepEqual(tf, want) {
		t.Errorf("Glob infra/*.tf = %v, want %v (must not recurse into subdirs)", tf, want)
	}

	auto, _ := m.Glob(filepath.Join("infra", "*.auto.tfvars"))
	if !reflect.DeepEqual(auto, []string{"infra/prod.auto.tfvars"}) {
		t.Errorf("Glob *.auto.tfvars = %v", auto)
	}

	// Root-level single file.
	root, _ := m.Glob("*.tf")
	if !reflect.DeepEqual(root, []string{"root.tf"}) {
		t.Errorf("Glob *.tf at root = %v", root)
	}

	// A non-matching glob returns empty and records nothing.
	none, _ := m.Glob(filepath.Join("nowhere", "*.tf"))
	if len(none) != 0 {
		t.Errorf("Glob non-match = %v, want empty", none)
	}
	if got := m.MissingFiles(); len(got) != 0 {
		t.Errorf("Glob must never record misses, got %v", got)
	}
}

func TestMemFS_ReadDir(t *testing.T) {
	m := newTestMemFS()

	entries, err := m.ReadDir("infra")
	if err != nil {
		t.Fatalf("ReadDir infra: %v", err)
	}
	got := map[string]bool{}
	for _, e := range entries {
		got[e.Name()] = e.IsDir()
	}
	want := map[string]bool{"main.tf": false, "variables.tf": false, "prod.auto.tfvars": false, "modules": true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ReadDir infra = %v, want %v", got, want)
	}

	// An absent module directory is recorded (the escalation signal).
	if _, err := m.ReadDir("infra/missingmod"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ReadDir miss err = %v, want ErrNotExist", err)
	}
	if got := m.MissingFiles(); !reflect.DeepEqual(got, []string{"infra/missingmod"}) {
		t.Errorf("MissingFiles after ReadDir miss = %v", got)
	}
}

// TestMemFS_ReadDirAbsoluteKeys covers the keys the server sees when the IDE
// analyzes a file that lives outside every workspace folder.
//
// The case worth pinning is ReadDir("."): synthesizing a directory's children
// takes each key's first path segment, and an absolute key's first segment is
// empty ("" for "/tmp/ws/main.tf"), which names no directory. There must be no
// entry called "" — a caller iterating the listing would go on to read a path
// that cannot exist. Nothing in the Terraform readers reaches ReadDir(".") with
// absolute keys today (every directory they derive from an absolute key stays
// absolute), so this guards a latent edge rather than a live one.
func TestMemFS_ReadDirAbsoluteKeys(t *testing.T) {
	m := NewMemFS(map[string][]byte{
		"/tmp/ws/main.tf":             []byte(`resource "aws_s3_bucket" "b" {}`),
		"/tmp/ws/variables.tf":        []byte(`variable "name" {}`),
		"/tmp/ws/modules/net/main.tf": []byte(`resource "x" "y" {}`),
	})

	entries, err := m.ReadDir("/tmp/ws")
	if err != nil {
		t.Fatalf("ReadDir /tmp/ws: %v", err)
	}
	got := map[string]bool{}
	for _, e := range entries {
		got[e.Name()] = e.IsDir()
	}
	want := map[string]bool{"main.tf": false, "variables.tf": false, "modules": true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ReadDir /tmp/ws = %v, want %v", got, want)
	}

	// "." holds nothing when every key is absolute: it must report a miss, not
	// a listing containing an unnamed directory.
	rootEntries, err := m.ReadDir(".")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ReadDir \".\" over absolute keys = (%v, %v), want ErrNotExist", rootEntries, err)
	}
	for _, e := range rootEntries {
		if e.Name() == "" {
			t.Errorf("ReadDir \".\" synthesized an entry with an empty name from an absolute key")
		}
	}
}

func TestMemFS_Paths(t *testing.T) {
	m := newTestMemFS()
	want := []string{"infra/main.tf", "infra/modules/net/main.tf", "infra/prod.auto.tfvars", "infra/variables.tf", "root.tf"}
	if got := m.Paths(); !reflect.DeepEqual(got, want) {
		t.Errorf("Paths = %v, want %v", got, want)
	}
}

// TestMemFS_DiskParity asserts MemFS matches DiskFS for the read operations the
// Terraform resolver relies on, so the content-push path produces the same
// results as the CLI for an equivalent file set.
func TestMemFS_DiskParity(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "main.tf"), `resource "x" "y" {}`)
	mustWrite(t, filepath.Join(dir, "vars.tf"), `variable "v" {}`)

	disk := DiskFS{}
	mem := NewMemFS(map[string][]byte{
		filepath.Join(dir, "main.tf"): []byte(`resource "x" "y" {}`),
		filepath.Join(dir, "vars.tf"): []byte(`variable "v" {}`),
	})

	dGlob, _ := disk.Glob(filepath.Join(dir, "*.tf"))
	mGlob, _ := mem.Glob(filepath.Join(dir, "*.tf"))
	// DiskFS returns OS-separated absolute paths; MemFS returns slash-normalized.
	if len(dGlob) != len(mGlob) {
		t.Errorf("Glob count: disk=%d mem=%d", len(dGlob), len(mGlob))
	}

	dContent, derr := disk.ReadFile(filepath.Join(dir, "main.tf"))
	mContent, merr := mem.ReadFile(filepath.Join(dir, "main.tf"))
	if derr != nil || merr != nil {
		t.Fatalf("ReadFile errors: disk=%v mem=%v", derr, merr)
	}
	if string(dContent) != string(mContent) {
		t.Errorf("ReadFile content mismatch: disk=%q mem=%q", dContent, mContent)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
