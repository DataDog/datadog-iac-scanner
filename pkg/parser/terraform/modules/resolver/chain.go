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
		if disposition, ok := unresolvedDisposition(err); ok {
			switch disposition {
			case tfmodules.ResolverDispositionDecline:
				failures.add(err)
				continue
			case tfmodules.ResolverDispositionTerminal:
				return Resolution{}, failures.withPrimary(err)
			case tfmodules.ResolverDispositionRetryable:
				var budgetErr *BudgetExceededError
				if errors.As(err, &budgetErr) {
					return Resolution{}, budgetErr
				}
				failures.add(err)
				continue
			}
		}
		var budgetErr *BudgetExceededError
		if errors.As(err, &budgetErr) {
			return Resolution{}, budgetErr
		}
		failures.add(err)
	}
	return Resolution{}, failures.err()
}

// unresolvedDisposition returns only recognized external dispositions. Legacy
// NotApplicable remains an explicit decline even when no disposition is set.
func unresolvedDisposition(err error) (tfmodules.ResolverDisposition, bool) {
	var unresolved *tfmodules.UnresolvedError
	if !errors.As(err, &unresolved) || unresolved.Disposition == "" {
		var verdict interface {
			ResolverDisposition() tfmodules.ResolverDisposition
		}
		if errors.As(err, &verdict) {
			return verdict.ResolverDisposition(), true
		}
		if unresolved == nil {
			return "", false
		}
	}
	switch unresolved.Disposition {
	case tfmodules.ResolverDispositionDecline, tfmodules.ResolverDispositionTerminal, tfmodules.ResolverDispositionRetryable:
		return unresolved.Disposition, true
	case "":
		if unresolved.NotApplicable {
			return tfmodules.ResolverDispositionDecline, true
		}
		// Legacy errors keep the original chain behavior: another resolver
		// may succeed. Diagnostic classification never controls routing.
		return "", false
	default:
		return tfmodules.ResolverDispositionRetryable, true
	}
}

func isResolverDecline(err error) bool {
	disposition, ok := unresolvedDisposition(err)
	return ok && disposition == tfmodules.ResolverDispositionDecline
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

// chainFailures keeps the reasons of resolvers that attempted a module apart
// from those that declined it, so a failure names what actually went wrong.
type chainFailures struct {
	attempted, declined []string
	causes              []error
}

func (f *chainFailures) add(err error) {
	reason := err.Error()
	var unresolved *tfmodules.UnresolvedError
	if errors.As(err, &unresolved) && isResolverDecline(err) {
		f.declined = append(f.declined, unresolved.Reason)
		return
	}
	// Keep the bare reason for direct unresolved errors, and the full wrapping
	// text when another error adds useful resolver context.
	if direct, ok := err.(*tfmodules.UnresolvedError); ok { //nolint:errorlint
		reason = direct.Reason
	}
	f.attempted = append(f.attempted, reason)
	f.causes = append(f.causes, err)
}

func (f *chainFailures) err() error {
	reasons := f.attempted
	if len(reasons) == 0 {
		reasons = f.declined
	}
	unresolved := &tfmodules.UnresolvedError{Reason: strings.Join(reasons, "; "), Cause: errors.Join(f.causes...)}
	if len(f.causes) == 0 {
		return unresolved
	}
	var attempts []FailureAttempt
	for _, cause := range f.causes {
		attempts = append(attempts, FailureAttempts(cause)...)
	}
	return &resolutionError{FailureDetails: DescribeFailure(unresolved), cause: unresolved, attempts: attempts}
}

// withPrimary retains earlier attempts as diagnostics without letting their
// causes (such as a timeout) override the definitive failure's classification.
func (f *chainFailures) withPrimary(err error) error {
	if len(f.causes) == 0 {
		return err
	}
	var attempts []FailureAttempt
	for _, cause := range f.causes {
		attempts = append(attempts, FailureAttempts(cause)...)
	}
	attempts = append(attempts, FailureAttempts(err)...)
	disposition, _ := unresolvedDisposition(err)
	return &resolutionError{FailureDetails: DescribeFailure(err), cause: err, attempts: attempts, disposition: disposition}
}
