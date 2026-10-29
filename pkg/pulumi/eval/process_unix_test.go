//go:build !windows

/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package eval

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// processGone reports whether pid no longer runs (absent, or a zombie waiting for its parent).
func processGone(pid int) bool {
	if runtime.GOOS == "linux" {
		b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
		if err != nil {
			return true
		}
		fields := strings.Fields(string(b[strings.LastIndexByte(string(b), ')')+1:]))
		return len(fields) > 0 && fields[0] == "Z"
	}
	return syscall.Kill(pid, 0) != nil
}
