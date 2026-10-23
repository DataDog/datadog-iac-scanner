//go:build linux || darwin

/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfscale

import (
	"os"
	"runtime"
	"syscall"
)

// kib is the unit Linux reports the maximum resident set size in.
const kib = 1024

// peakRSS is the child's maximum resident set size in bytes.
func peakRSS(state *os.ProcessState) int64 {
	ru, ok := state.SysUsage().(*syscall.Rusage)
	if !ok {
		return 0
	}
	if runtime.GOOS == "darwin" {
		return ru.Maxrss
	}
	return ru.Maxrss * kib
}
