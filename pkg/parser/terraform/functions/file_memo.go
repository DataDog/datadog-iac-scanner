/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"encoding/base64"
	"errors"
	"unicode/utf8"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/zclconf/go-cty/cty"
)

// fileKey names what a file function made of the file at a confined path.
type fileKey struct {
	fn   string
	path string
}

type fileResult struct {
	value cty.Value
	err   error
	// size is the length of the file read.
	size int
}

// errInvalidUTF8 stands for content file rejects; the caller names the path
// as it was written in the call.
var errInvalidUTF8 = errors.New("invalid UTF-8")

// readFileResult returns what derive makes of the file at full, a path
// confinePath accepted. Through a ScanFS, calls reading the same file share
// one read and one result for the rest of the scan.
func readFileResult(fsys vfs.FS, fn, full string, derive func([]byte) fileResult) fileResult {
	read := func() fileResult {
		src, err := fsys.ReadFile(full)
		if err != nil {
			return fileResult{err: err}
		}
		r := derive(src)
		r.size = len(src)
		return r
	}
	s, ok := fsys.(*ScanFS)
	if !ok {
		return read()
	}
	return s.memo.files.lookupOrCompute(fileKey{fn: fn, path: s.realPath(full)}, read)
}

func estimateFile(key fileKey, r fileResult) (int, bool) {
	n := retainedEntry + len(key.path)
	switch {
	case r.err != nil:
		return n + estimateError(r.err), true
	case r.size < minMemoizedSize:
		return 0, false
	}
	return n + estimateValue(r.value), true
}

// outputString is the string every call returning r passes on.
func (r fileResult) outputString() (string, bool) {
	return stringOutput(r.value, r.err)
}

func stringOutput(v cty.Value, err error) (string, bool) {
	if err != nil || v == cty.NilVal || !v.Type().Equals(cty.String) || !v.IsKnown() || v.IsNull() {
		return "", false
	}
	return v.AsString(), true
}

func fileText(src []byte) fileResult {
	if !utf8.Valid(src) {
		return fileResult{err: errInvalidUTF8}
	}
	return fileResult{value: cty.StringVal(string(src))}
}

func fileBase64(src []byte) fileResult {
	return fileResult{value: cty.StringVal(base64.StdEncoding.EncodeToString(src))}
}
