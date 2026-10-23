//go:build !linux && !darwin

/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfscale

import "os"

func peakRSS(*os.ProcessState) int64 { return 0 }
