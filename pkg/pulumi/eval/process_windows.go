//go:build windows

/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package eval

import "os/exec"

// osSupported reports whether this OS can run evaluations. On Windows the
// scanner cannot kill a program's whole process tree yet (Job Objects are a
// follow-up), so it executes nothing (D20).
const osSupported = false

func setProcessGroup(*exec.Cmd) {}

func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
