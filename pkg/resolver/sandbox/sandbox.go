// Package sandbox: per-scan temp dirs for preprocessors.
package sandbox

import (
	"os"
)

// Sandbox is a per-scan writable temp directory (0700 from MkdirTemp on Unix), removed on Close.
type Sandbox struct {
	RepoRoot   string
	ScratchDir string
}

// New creates a sandbox under the OS temp directory (MkdirTemp uses 0700 on Unix).
func New() (*Sandbox, error) {
	t, err := os.MkdirTemp("", "datadog-iac-scanner-")
	if err != nil {
		return nil, err
	}
	return &Sandbox{ScratchDir: t}, nil
}

// Close removes the scratch directory (idempotent).
func (s *Sandbox) Close() error {
	if s == nil || s.ScratchDir == "" {
		return nil
	}
	err := os.RemoveAll(s.ScratchDir)
	s.ScratchDir = ""
	return err
}
