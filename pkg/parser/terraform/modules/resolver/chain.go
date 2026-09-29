/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"errors"
	"strings"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

// ChainResolver tries each Resolver in order.
type ChainResolver struct {
	resolvers []Resolver
}

func NewChainResolver(resolvers ...Resolver) *ChainResolver {
	return &ChainResolver{resolvers: resolvers}
}

// notApplicable reports that a resolver does not handle a source, so the chain
// can leave it out of the failure reason when another resolver attempted it.
func notApplicable(reason string) error {
	return &tfmodules.UnresolvedError{Reason: reason, NotApplicable: true}
}

func (c *ChainResolver) Resolve(ctx context.Context, mod *tfmodules.ParsedModule) (Resolution, error) {
	if len(c.resolvers) == 0 {
		return Resolution{}, &tfmodules.UnresolvedError{Reason: "no resolvers configured"}
	}
	var failures chainFailures
	for _, r := range c.resolvers {
		res, err := r.Resolve(ctx, mod)
		if err == nil {
			return res, nil
		}
		var budgetErr *BudgetExceededError
		if errors.As(err, &budgetErr) {
			return Resolution{}, budgetErr
		}
		failures.add(err)
	}
	return Resolution{}, failures.err()
}

// Screen returns the error Resolve would return for mod when every resolver in
// the chain rules it out, and nil as soon as one might resolve it or cannot tell.
func (c *ChainResolver) Screen(ctx context.Context, mod *tfmodules.ParsedModule) error {
	if len(c.resolvers) == 0 {
		return &tfmodules.UnresolvedError{Reason: "no resolvers configured"}
	}
	var failures chainFailures
	for _, r := range c.resolvers {
		screener, ok := r.(Screener)
		if !ok {
			return nil
		}
		err := screener.Screen(ctx, mod)
		if err == nil {
			return nil
		}
		failures.add(err)
	}
	return failures.err()
}

// chainFailures keeps the reasons of resolvers that attempted a module apart
// from those that declined it, so a failure names what actually went wrong.
type chainFailures struct {
	attempted, declined []string
}

func (f *chainFailures) add(err error) {
	reason := err.Error()
	// Wrapped errors keep their full text so the wrapping context survives.
	if unresolved, ok := err.(*tfmodules.UnresolvedError); ok { //nolint:errorlint
		reason = unresolved.Reason
		if unresolved.NotApplicable {
			f.declined = append(f.declined, reason)
			return
		}
	}
	f.attempted = append(f.attempted, reason)
}

func (f *chainFailures) err() error {
	reasons := f.attempted
	if len(reasons) == 0 {
		reasons = f.declined
	}
	return &tfmodules.UnresolvedError{Reason: strings.Join(reasons, "; ")}
}
