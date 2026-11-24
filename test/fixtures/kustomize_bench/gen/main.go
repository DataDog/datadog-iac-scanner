// Command gen writes the Kustomize performance bench tree to a directory:
// bases with deployments, four overlays per base (one patching, one with a
// generator), everything a scan needs to render. Nothing large is committed:
// the tree is generated into a scratch directory, initialized as a git
// repository with an origin remote and committed before a scan.
//
//	go run ./test/fixtures/kustomize_bench/gen /tmp/kbench
//	cd /tmp/kbench && git init -q && git remote add origin https://example.invalid/fixture.git &&
//		git add -A && git -c user.email=bench@local -c user.name=bench commit -qm bench
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// Permissions for the generated tree; constants keep the linter's magic
// number check quiet.
const (
	dirPerm  os.FileMode = 0o750
	filePerm os.FileMode = 0o600
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gen <dir>")
		os.Exit(2)
	}
	root := os.Args[1]
	if err := os.MkdirAll(root, dirPerm); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	bases := 30
	if n := os.Getenv("BENCH_BASES"); n != "" {
		if _, err := fmt.Sscanf(n, "%d", &bases); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	docsPerBase := 20
	if n := os.Getenv("BENCH_DOCS"); n != "" {
		if _, err := fmt.Sscanf(n, "%d", &docsPerBase); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	for b := 0; b < bases; b++ {
		if err := writeBase(root, b, docsPerBase); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for o := 0; o < 4; o++ {
			if err := writeOverlay(root, b, o); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
	}
}

func writeBase(root string, b, docs int) error {
	base := filepath.Join(root, fmt.Sprintf("base%02d", b))
	if err := os.MkdirAll(base, dirPerm); err != nil {
		return err
	}
	res := "resources:\n"
	for d := 0; d < docs; d++ {
		body := fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: app%d-%d
spec:
  template:
    spec:
      containers:
        - name: c
          image: nginx
          securityContext:
            privileged: false
`, b, d)
		if err := os.WriteFile(filepath.Join(base, fmt.Sprintf("w%d.yaml", d)), []byte(body), filePerm); err != nil {
			return err
		}
		res += fmt.Sprintf("  - w%d.yaml\n", d)
	}
	return os.WriteFile(filepath.Join(base, "kustomization.yaml"), []byte(res), filePerm)
}

func writeOverlay(root string, b, o int) error {
	ov := filepath.Join(root, fmt.Sprintf("base%02d-overlays/ov%d", b, o))
	if err := os.MkdirAll(ov, dirPerm); err != nil {
		return err
	}
	kust := fmt.Sprintf("resources:\n  - ../../base%02d\n", b)
	if o == 0 {
		body := fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: app%d-0
spec:
  template:
    spec:
      containers:
        - name: c
          securityContext:
            privileged: true
`, b)
		if err := os.WriteFile(filepath.Join(ov, "patch.yaml"), []byte(body), filePerm); err != nil {
			return err
		}
		kust += "patches:\n  - path: patch.yaml\n"
	}
	if o == 3 {
		kust += fmt.Sprintf("configMapGenerator:\n  - name: cm%d\n    literals:\n      - KEY=value\n", b)
	}
	return os.WriteFile(filepath.Join(ov, "kustomization.yaml"), []byte(kust), filePerm)
}
