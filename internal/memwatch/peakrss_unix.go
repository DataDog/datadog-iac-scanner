//go:build linux || darwin

/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package memwatch

import "syscall"

func peakRSSBytes() (uint64, bool) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, false
	}
	if ru.Maxrss < 0 {
		return 0, false
	}

	return uint64(ru.Maxrss) * maxrssUnitBytes, true
}
