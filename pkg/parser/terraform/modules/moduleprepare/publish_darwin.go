//go:build darwin

/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package moduleprepare

import "golang.org/x/sys/unix"

func publishArtifact(source, destination string) error {
	return unix.RenamexNp(source, destination, unix.RENAME_EXCL)
}
