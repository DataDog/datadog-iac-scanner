/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"testing"
)

func TestGitModuleResolveKeyFoldsTransport(t *testing.T) {
	https := "git::https://github.com/org/repo.git//terraform-modules/aws-bucket?ref=aws-bucket_v7.1.2"
	ssh := "git::ssh://git@github.com/org/repo//terraform-modules/aws-bucket?ref=aws-bucket_v7.1.2"
	scp := "git@github.com:org/repo//terraform-modules/aws-bucket?ref=aws-bucket_v7.1.2"

	keyHTTPS, ok := GitModuleResolveKey(https, "")
	if !ok {
		t.Fatal("expected https key")
	}
	keySSH, ok := GitModuleResolveKey(ssh, "")
	if !ok {
		t.Fatal("expected ssh key")
	}
	keySCP, ok := GitModuleResolveKey(scp, "")
	if !ok {
		t.Fatal("expected scp key")
	}
	if keyHTTPS != keySSH || keyHTTPS != keySCP {
		t.Fatalf("keys differ:\n  https=%q\n  ssh=%q\n  scp=%q", keyHTTPS, keySSH, keySCP)
	}
	want := "github.com/org/repo\x00aws-bucket_v7.1.2\x00terraform-modules/aws-bucket"
	if keyHTTPS != want {
		t.Fatalf("key = %q, want %q", keyHTTPS, want)
	}
}

func TestGitModuleResolveKeyDifferentSubdirs(t *testing.T) {
	a, ok := GitModuleResolveKey("git::https://github.com/org/repo//mods/a?ref=v1", "")
	if !ok {
		t.Fatal("expected ok")
	}
	b, ok := GitModuleResolveKey("git::https://github.com/org/repo//mods/b?ref=v1", "")
	if !ok {
		t.Fatal("expected ok")
	}
	if a == b {
		t.Fatal("different subdirs must not share a resolve key")
	}
}

func TestBareGitOwnsSource(t *testing.T) {
	if !bareGitOwnsSource("git::https://github.com/org/repo//sub?ref=v1") {
		t.Fatal("git:: with ref should be bare-git owned")
	}
	if bareGitOwnsSource("git::https://github.com/org/repo//sub") {
		t.Fatal("git:: without ref is not bare-git owned")
	}
	if bareGitOwnsSource("registry.terraform.io/org/name/aws") {
		t.Fatal("registry source is not bare-git owned")
	}
}
