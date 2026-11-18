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
	if err := tfmodules.ValidateModuleSource(mod.Source); err != nil {
		return Resolution{}, err
	}
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
	if err := tfmodules.ValidateModuleSource(mod.Source); err != nil {
		return err
	}
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

// chainFailures keeps the failures of resolvers that attempted a module apart
// from those that declined it, so a failure names what actually went wrong.
type chainFailures struct {
	attempted, declined []chainFailure
}

type chainFailure struct {
	reason, code, detail string
}

func (f *chainFailures) add(err error) {
	// A wrapped error keeps its full text as the reason, so the wrapping context
	// survives. Its code and detail are still read, as the classification does.
	failure := chainFailure{reason: err.Error()}
	var unresolved *tfmodules.UnresolvedError
	if errors.As(err, &unresolved) {
		failure.code, failure.detail = unresolved.Code, unresolved.Detail
	}
	if direct, ok := err.(*tfmodules.UnresolvedError); ok { //nolint:errorlint
		failure = chainFailure{reason: direct.Reason, code: direct.Code, detail: direct.Detail}
		if direct.NotApplicable {
			f.declined = append(f.declined, failure)
			return
		}
	}
	f.attempted = append(f.attempted, failure)
}

// err joins the reasons and details of the failures. The code is the first one
// a resolver set, in chain order: a resolver that answers authoritatively names
// the failure even when a later resolver also fails, for example by cloning
// the repository anonymously.
func (f *chainFailures) err() error {
	failures := f.attempted
	if len(failures) == 0 {
		failures = f.declined
	}
	reasons := make([]string, 0, len(failures))
	details := make([]string, 0, len(failures))
	err := &tfmodules.UnresolvedError{}
	for _, failure := range failures {
		reasons = append(reasons, failure.reason)
		if failure.detail != "" {
			details = append(details, failure.detail)
		}
		if err.Code == "" {
			err.Code = failure.code
		}
	}
	err.Reason = strings.Join(reasons, "; ")
	err.Detail = tfmodules.FailureDetail(strings.Join(details, "; "))
	return err
}
