/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

// LocalResolver resolves local filesystem module sources.
type LocalResolver struct{}

func (LocalResolver) Resolve(_ context.Context, mod *tfmodules.ParsedModule) (Resolution, error) {
	if !mod.IsLocal {
		return Resolution{}, &tfmodules.UnresolvedError{Reason: "not a local module"}
	}
	if mod.AbsSource == "" {
		return Resolution{}, &tfmodules.UnresolvedError{Reason: "local module has no resolved absolute path"}
	}
	return Resolution{LocalPath: mod.AbsSource}, nil
}
