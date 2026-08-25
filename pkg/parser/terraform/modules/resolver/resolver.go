/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package resolver implements Terraform module resolution for tfmodules.RemoteResolver.
package resolver

import (
	"context"
	"sync"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

// Resolution holds an acquired package, its selected module directory, and optional cleanup.
type Resolution struct {
	LocalPath   string
	PackageRoot string
	Cleanup     func() // optional post-scan cleanup
}

func withResolutionCleanup(res Resolution, cleanup func()) Resolution {
	previous := res.Cleanup
	var once sync.Once
	res.Cleanup = func() {
		once.Do(func() {
			if previous != nil {
				previous()
			}
			if cleanup != nil {
				cleanup()
			}
		})
	}
	return res
}

// Resolver maps one module call to disk; errors should wrap *tfmodules.UnresolvedError when appropriate.
type Resolver interface {
	Resolve(ctx context.Context, mod *tfmodules.ParsedModule) (Resolution, error)
}
