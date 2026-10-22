/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package memwatch

import (
	"math"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
)

// Limit returns the memory the process may use: the Go memory limit when one
// is set, otherwise the tightest of the cgroup limit and the machine's
// memory. ok is false when none is known.
func Limit() (limit uint64, ok bool) {
	if l := debug.SetMemoryLimit(-1); l > 0 && l < math.MaxInt64 {
		return uint64(l), true
	}
	return systemLimit()
}

// systemLimit is the tightest of the cgroup v2 and v1 limits and MemTotal.
func systemLimit() (uint64, bool) {
	var best uint64
	consider := func(v uint64, ok bool) {
		if ok && v > 0 && (best == 0 || v < best) {
			best = v
		}
	}
	consider(readLimitFile("/sys/fs/cgroup/memory.max"))
	consider(readLimitFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"))
	consider(memTotal())
	return best, best > 0
}

// readLimitFile reads a cgroup limit, which "max" or an absurdly large value
// marks as unlimited.
func readLimitFile(path string) (uint64, bool) {
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(b))
	if s == "max" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v >= 1<<60 {
		return 0, false
	}
	return v, true
}

// bytesPerKiB converts the kB unit /proc/meminfo reports in.
const bytesPerKiB = 1024

func memTotal() (uint64, bool) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		rest, ok := strings.CutPrefix(line, "MemTotal:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return 0, false
		}
		kb, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0, false
		}
		return kb * bytesPerKiB, true
	}
	return 0, false
}

// goMemLimitShare is the share of the known memory limit the Go runtime is
// asked to stay within, leaving room for memory it does not manage.
const goMemLimitShare = 0.9

// ApplyGoMemLimit sets the Go memory limit from the system limit unless the
// environment sets one, so the garbage collector works harder as the process
// approaches the limit instead of the process being killed at it.
func ApplyGoMemLimit() {
	if _, set := os.LookupEnv("GOMEMLIMIT"); set {
		return
	}
	if limit, ok := systemLimit(); ok {
		debug.SetMemoryLimit(int64(float64(limit) * goMemLimitShare))
	}
}
