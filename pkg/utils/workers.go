/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package utils

import "runtime"

func AdjustNumWorkers(workers int) int {
	// for the case in which the end user decides to use num workers as "auto-detected"
	// we will set the number of workers to the number of CPUs available based on GOMAXPROCS value
	if workers == 0 {
		return runtime.GOMAXPROCS(-1)
	}
	return workers
}
