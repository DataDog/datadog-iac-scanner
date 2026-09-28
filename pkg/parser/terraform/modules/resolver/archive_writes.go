/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// archiveWrites records the paths an extraction creates, in creation order, and
// the on-disk usage they add, so a failed extraction can be undone without
// snapshotting the tree beforehand. A nil *archiveWrites creates without recording.
type archiveWrites struct {
	paths []string
	usage PackageUsage
}

func (w *archiveWrites) mkdirAll(path string) error {
	if w == nil {
		return os.MkdirAll(path, dirPerm)
	}
	var missing []string
	for dir := filepath.Clean(path); ; dir = filepath.Dir(dir) {
		_, err := os.Lstat(dir)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		missing = append(missing, dir)
		if filepath.Dir(dir) == dir {
			break
		}
	}
	err := os.MkdirAll(path, dirPerm)
	for i := len(missing) - 1; i >= 0; i-- {
		if _, statErr := os.Lstat(missing[i]); statErr != nil {
			break
		}
		w.paths = append(w.paths, missing[i])
		w.usage.Files++
	}
	return err
}

// addFile records a regular file before it is written, so a partial write is
// still removed on rollback.
func (w *archiveWrites) addFile(path string, size int64) {
	if w == nil {
		return
	}
	w.paths = append(w.paths, path)
	w.usage.Files++
	w.usage.Bytes += size
}

func (w *archiveWrites) merge(other *archiveWrites) {
	w.paths = append(w.paths, other.paths...)
	w.usage.Files += other.usage.Files
	w.usage.Bytes += other.usage.Bytes
}

// rollback removes the recorded paths newest first, so each directory is empty
// by the time it is removed. On failure the paths not yet removed stay recorded.
func (w *archiveWrites) rollback() error {
	for i := len(w.paths) - 1; i >= 0; i-- {
		if err := os.Remove(w.paths[i]); err != nil && !errors.Is(err, os.ErrNotExist) {
			w.paths = w.paths[:i+1]
			return err
		}
	}
	w.paths = nil
	w.usage = PackageUsage{}
	return nil
}

// archiveUsages maps a sparse archive root to its exact on-disk usage. Roots are
// only written under their archiveMaterializeLock, so once one is recorded this
// process can reuse the value instead of walking the tree again.
var archiveUsages sync.Map

func knownArchiveUsage(root string) (PackageUsage, bool) {
	usage, ok := archiveUsages.Load(filepath.Clean(root))
	if !ok {
		return PackageUsage{}, false
	}
	return usage.(PackageUsage), true
}

func archiveUsageHint(root string) *PackageUsage {
	usage, ok := knownArchiveUsage(root)
	if !ok {
		return nil
	}
	return &usage
}

func storeArchiveUsage(root string, usage PackageUsage) {
	archiveUsages.Store(filepath.Clean(root), usage)
}

func forgetArchiveUsage(root string) {
	archiveUsages.Delete(filepath.Clean(root))
}
