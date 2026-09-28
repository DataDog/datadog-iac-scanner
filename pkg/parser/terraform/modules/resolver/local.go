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

func (LocalResolver) Screen(_ context.Context, mod *tfmodules.ParsedModule) error {
	if !mod.IsLocal {
		return notApplicable("not a local module")
	}
	return nil
}

func (r LocalResolver) Resolve(ctx context.Context, mod *tfmodules.ParsedModule) (Resolution, error) {
	if err := r.Screen(ctx, mod); err != nil {
		return Resolution{}, err
	}
	if mod.AbsSource == "" {
		return Resolution{}, &tfmodules.UnresolvedError{Reason: "local module has no resolved absolute path"}
	}
	return Resolution{LocalPath: mod.AbsSource, Origin: "local"}, nil
}
