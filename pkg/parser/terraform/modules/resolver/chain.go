/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"errors"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

// ChainResolver tries each Resolver in order.
type ChainResolver struct {
	resolvers []Resolver
}

func NewChainResolver(resolvers ...Resolver) *ChainResolver {
	return &ChainResolver{resolvers: resolvers}
}

func (c *ChainResolver) Resolve(ctx context.Context, mod *tfmodules.ParsedModule) (Resolution, error) {
	if len(c.resolvers) == 0 {
		return Resolution{}, &tfmodules.UnresolvedError{Reason: "no resolvers configured"}
	}
	var errs []error
	for _, r := range c.resolvers {
		res, err := r.Resolve(ctx, mod)
		if err == nil {
			return res, nil
		}
		errs = append(errs, err)
	}
	return Resolution{}, &tfmodules.UnresolvedError{Reason: errors.Join(errs...).Error()}
}
