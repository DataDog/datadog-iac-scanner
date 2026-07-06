/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"runtime"
)

const gitSHALength = 40

// gitProcSem caps concurrent git subprocesses across resolvers.
var gitProcSem = make(chan struct{}, gitProcConcurrency())

func gitProcConcurrency() int {
	n := runtime.GOMAXPROCS(0)
	const floor = 4
	if n < floor {
		return floor
	}
	return n
}

func acquireGitProc(ctx context.Context) (release func(), err error) {
	select {
	case gitProcSem <- struct{}{}:
		return func() { <-gitProcSem }, nil
	case <-ctx.Done():
		return func() {}, ctx.Err()
	}
}

// looksLikeSHA reports whether ref is a full 40-character hex SHA-1.
func looksLikeSHA(ref string) bool {
	if len(ref) != gitSHALength {
		return false
	}
	for _, c := range ref {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
