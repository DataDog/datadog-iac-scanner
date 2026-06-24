/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package vfs abstracts the file-reading operations the scanner performs during
// cross-file resolution (Terraform sibling/variable globs, module directory
// reads, $ref includes). The CLI uses DiskFS — a thin passthrough to the real
// filesystem, behaviorally identical to direct os.* calls. The HTTP server uses
// an in-memory implementation built from content pushed over the wire, so it can
// resolve unsaved editor buffers and browser web-shell files that never touch
// disk.
//
// The interface deliberately mirrors os/filepath (absolute OS paths, filepath
// glob semantics) rather than io/fs.FS, because the readers it serves operate on
// absolute paths and use filepath.Glob.
package vfs

import (
	"io/fs"
	"os"
	"path/filepath"
)

// FS is the set of read operations the cross-file resolution code performs.
type FS interface {
	// ReadFile reads the named file and returns its contents.
	ReadFile(name string) ([]byte, error)
	// Stat returns file info for the named file.
	Stat(name string) (fs.FileInfo, error)
	// ReadDir reads the named directory, returning its entries.
	ReadDir(name string) ([]fs.DirEntry, error)
	// Glob returns the names matching pattern (filepath.Glob semantics).
	Glob(pattern string) ([]string, error)
	// Abs resolves name against the filesystem's root.
	Abs(name string) (string, error)
}

// DiskFS is the real-filesystem implementation used by the CLI. Each method is a
// direct passthrough to os/filepath, so threading DiskFS through the resolution
// code is behavior-preserving.
type DiskFS struct{}

// ReadFile reads the named file from disk.
func (DiskFS) ReadFile(name string) ([]byte, error) { return os.ReadFile(name) } //nolint:gosec

// Stat stats the named file on disk.
func (DiskFS) Stat(name string) (fs.FileInfo, error) { return os.Stat(name) }

// ReadDir reads the named directory from disk.
func (DiskFS) ReadDir(name string) ([]fs.DirEntry, error) { return os.ReadDir(name) }

// Glob returns the files on disk matching pattern.
func (DiskFS) Glob(pattern string) ([]string, error) { return filepath.Glob(pattern) }

// Abs resolves name against the process working directory.
func (DiskFS) Abs(name string) (string, error) { return filepath.Abs(name) }

// Default returns the filesystem used when none is injected (the real disk).
func Default() FS { return DiskFS{} }

var _ FS = DiskFS{}
