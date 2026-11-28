//go:build windows

/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package eval

// processGone is not used on Windows: evaluation executes nothing there.
func processGone(int) bool { return true }
