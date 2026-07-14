/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package resolver implements Terraform module resolution for tfmodules.RemoteResolver.
package resolver

import (
	"context"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

// Resolution holds a resolved module directory and optional cleanup.
type Resolution struct {
	LocalPath        string
	RequestedVersion string
	ResolvedVersion  string
	CanonicalSource  string
	ContentDigest    string
	Provenance       string
	Outcome          string
	Cleanup          func() // optional post-scan cleanup
}

// Resolver maps one module call to disk; errors should wrap *tfmodules.UnresolvedError when appropriate.
type Resolver interface {
	Resolve(ctx context.Context, mod *tfmodules.ParsedModule) (Resolution, error)
}
