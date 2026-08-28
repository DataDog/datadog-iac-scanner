//go:build !linux && !darwin

/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package memwatch

func peakRSSBytes() (uint64, bool) {
	return 0, false
}
