/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

const (
	filePerms = 0o644
	dirPerms  = 0o755
)

// ErrNotInventory reports something at the inventory path that no scan wrote
// as an inventory, such as a report or a scanned file: it must be neither
// removed nor replaced.
var ErrNotInventory = errors.New("the path holds something other than an inventory")

// inventoryHeadKeys are the fields every inventory starts with, in the
// order encode writes them, all strings. Reading them takes the start of the
// file only, never the lists that follow.
var inventoryHeadKeys = []string{"schema_version", "scan_id", "scanner_version", "scanned_at"}

// inventoryHeadLimit bounds how much of a file is read to recognize it.
const inventoryHeadLimit = 64 << 10

// RemoveStale deletes an inventory left at path by an earlier scan, so that a
// scan which ends without writing one leaves no file behind. Anything else at
// path is left as it is, and reported as ErrNotInventory.
func RemoveStale(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || !isInventory(path) {
		return ErrNotInventory
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// isInventory reports whether the file at path starts as an inventory does.
func isInventory(path string) bool {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	dec := json.NewDecoder(io.LimitReader(f, inventoryHeadLimit))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return false
	}
	for _, key := range inventoryHeadKeys {
		if tok, err := dec.Token(); err != nil || tok != any(key) {
			return false
		}
		value, err := dec.Token()
		text, ok := value.(string)
		if err != nil || !ok || (key == "schema_version" && text != SchemaVersion) {
			return false
		}
	}
	return true
}

// WriteFile writes inv to path atomically: it is written to a temporary file
// in the same directory and renamed into place, so a reader finds either no
// file or a complete one.
func WriteFile(path string, inv *Inventory) error {
	// Created only now, after the reports: an inventory directory must never
	// take the place of a report.
	if err := os.MkdirAll(filepath.Dir(path), dirPerms); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	renamed := false
	// Also on a panic, the temporary file does not stay behind.
	defer func() {
		if !renamed {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if err := fill(tmp, inv); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	renamed = true
	return nil
}

// fill writes inv to f, flushed to disk, and closes f.
func fill(f *os.File, inv *Inventory) error {
	w := bufio.NewWriter(f)
	if err := encode(w, inv); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if err := f.Chmod(filePerms); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Close()
}

// inventoryHead is Inventory without its lists, which come last.
type inventoryHead struct {
	SchemaVersion    string     `json:"schema_version"`
	ScanID           string     `json:"scan_id"`
	ScannerVersion   string     `json:"scanner_version"`
	ScannedAt        time.Time  `json:"scanned_at"`
	Repository       Repository `json:"repository"`
	Status           string     `json:"status"`
	PlatformsScanned []string   `json:"platforms_scanned"`
	Stats            Stats      `json:"stats"`
}

// encode writes inv as JSON followed by a newline, as json.Encoder with HTML
// escaping off would, one list entry at a time: an inventory can hold tens
// of thousands of rows, which would otherwise be encoded in memory at once.
func encode(w io.Writer, inv *Inventory) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	put := func(v any) ([]byte, error) {
		buf.Reset()
		if err := enc.Encode(v); err != nil {
			return nil, err
		}
		return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
	}
	head, err := put(inventoryHead{
		SchemaVersion: inv.SchemaVersion, ScanID: inv.ScanID, ScannerVersion: inv.ScannerVersion,
		ScannedAt: inv.ScannedAt, Repository: inv.Repository, Status: inv.Status,
		PlatformsScanned: inv.PlatformsScanned, Stats: inv.Stats,
	})
	if err != nil {
		return err
	}
	if _, err := w.Write(bytes.TrimSuffix(head, []byte("}"))); err != nil {
		return err
	}
	lists := []struct {
		name  string
		count int
		item  func(int) any
	}{
		{"files", len(inv.Files), func(i int) any { return &inv.Files[i] }},
		{"unresolved_sources", len(inv.UnresolvedSources), func(i int) any { return &inv.UnresolvedSources[i] }},
		{"resources", len(inv.Resources), func(i int) any { return &inv.Resources[i] }},
		{"finding_links", len(inv.FindingLinks), func(i int) any { return &inv.FindingLinks[i] }},
	}
	for _, list := range lists {
		if _, err := io.WriteString(w, `,"`+list.name+`":[`); err != nil {
			return err
		}
		for i := 0; i < list.count; i++ {
			if i > 0 {
				if _, err := io.WriteString(w, ","); err != nil {
					return err
				}
			}
			item, err := put(list.item(i))
			if err != nil {
				return err
			}
			if _, err := w.Write(item); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(w, "]"); err != nil {
			return err
		}
	}
	_, err = io.WriteString(w, "}\n")
	return err
}
