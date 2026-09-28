/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com/)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

// fakeChainResolver adapts a function to Resolver so table tests can script
// per-resolver outcomes without touching the network or the filesystem.
type fakeChainResolver func(ctx context.Context, mod *tfmodules.ParsedModule) (Resolution, error)

func (f fakeChainResolver) Resolve(ctx context.Context, mod *tfmodules.ParsedModule) (Resolution, error) {
	return f(ctx, mod)
}

func decliningResolver(reason string) Resolver {
	return fakeChainResolver(func(context.Context, *tfmodules.ParsedModule) (Resolution, error) {
		return Resolution{}, notApplicable(reason)
	})
}

func failingResolver(err error) Resolver {
	return fakeChainResolver(func(context.Context, *tfmodules.ParsedModule) (Resolution, error) {
		return Resolution{}, err
	})
}

func succeedingResolver(localPath string) Resolver {
	return fakeChainResolver(func(context.Context, *tfmodules.ParsedModule) (Resolution, error) {
		return Resolution{LocalPath: localPath, Origin: "fake"}, nil
	})
}

func unresolvedReason(t *testing.T, err error) string {
	t.Helper()
	var unresolved *tfmodules.UnresolvedError
	require.ErrorAs(t, err, &unresolved)
	return unresolved.Reason
}

func TestChainResolver(t *testing.T) {
	ctx := context.Background()
	mod := &tfmodules.ParsedModule{Name: "network", Source: "registry.example.com/network/aws"}

	t.Run("first success returns immediately", func(t *testing.T) {
		afterSuccessCalled := false
		res, err := NewChainResolver(
			failingResolver(&tfmodules.UnresolvedError{Reason: "attempted but failed"}),
			succeedingResolver("/modules/network"),
			fakeChainResolver(func(context.Context, *tfmodules.ParsedModule) (Resolution, error) {
				afterSuccessCalled = true
				return Resolution{LocalPath: "/modules/other"}, nil
			}),
		).Resolve(ctx, mod)
		require.NoError(t, err)
		require.Equal(t, "/modules/network", res.LocalPath)
		require.False(t, afterSuccessCalled, "resolvers after a success must not run")
	})

	t.Run("empty chain reports no resolvers configured", func(t *testing.T) {
		_, err := NewChainResolver().Resolve(ctx, mod)
		require.Error(t, err)
		require.Equal(t, "no resolvers configured", unresolvedReason(t, err))
	})

	t.Run("declined resolvers dropped when another resolver attempted", func(t *testing.T) {
		_, err := NewChainResolver(
			decliningResolver("local modules are handled by LocalResolver"),
			failingResolver(&tfmodules.UnresolvedError{Reason: "attempted a"}),
			decliningResolver("module not found in manifest"),
			failingResolver(&tfmodules.UnresolvedError{Reason: "attempted b"}),
		).Resolve(ctx, mod)
		require.Error(t, err)
		require.Equal(t, "attempted a; attempted b", unresolvedReason(t, err))

		var unresolved *tfmodules.UnresolvedError
		require.ErrorAs(t, err, &unresolved)
		require.False(t, unresolved.NotApplicable, "the chain failure is an attempted failure, not a decline")
	})

	t.Run("declined-only fallback when nothing was attempted", func(t *testing.T) {
		_, err := NewChainResolver(
			decliningResolver("declined a"),
			decliningResolver("declined b"),
		).Resolve(ctx, mod)
		require.Error(t, err)
		require.Equal(t, "declined a; declined b", unresolvedReason(t, err))
	})

	t.Run("budget error short-circuits the chain", func(t *testing.T) {
		wrappedBudget := fmt.Errorf("module package rejected: %w", &BudgetExceededError{
			Gate:     "acquisition",
			Limit:    "module_bytes_total",
			Maximum:  10,
			Measured: 20,
		})
		afterBudgetCalled := false
		_, err := NewChainResolver(
			failingResolver(&tfmodules.UnresolvedError{Reason: "attempted before the budget error"}),
			failingResolver(wrappedBudget),
			fakeChainResolver(func(context.Context, *tfmodules.ParsedModule) (Resolution, error) {
				afterBudgetCalled = true
				return Resolution{}, &tfmodules.UnresolvedError{Reason: "should never run"}
			}),
		).Resolve(ctx, mod)
		require.Error(t, err)

		var budgetErr *BudgetExceededError
		require.ErrorAs(t, err, &budgetErr, "the budget error must propagate, not become an UnresolvedError")
		require.Equal(t, "acquisition", budgetErr.Gate)
		require.False(t, afterBudgetCalled, "resolvers after a budget error must not run")
	})

	t.Run("wrapped non-UnresolvedError errors keep their full text", func(t *testing.T) {
		_, err := NewChainResolver(
			failingResolver(fmt.Errorf("fetching module: %w", &tfmodules.UnresolvedError{Reason: "inner reason"})),
			failingResolver(errors.New("plain failure")),
		).Resolve(ctx, mod)
		require.Error(t, err)
		// The wrapped error never unwraps to a bare Reason: its whole Error()
		// text survives, so callers keep the wrapping context.
		require.Equal(t,
			"fetching module: module unresolved: inner reason; plain failure",
			unresolvedReason(t, err))
	})
}

// fakeScreener is a resolver whose Screen outcome is scripted; Resolve fails
// the test because screening must never resolve anything.
type fakeScreener struct {
	t      *testing.T
	screen error
}

func (f fakeScreener) Resolve(context.Context, *tfmodules.ParsedModule) (Resolution, error) {
	f.t.Fatal("Screen must not call Resolve")
	return Resolution{}, nil
}

func (f fakeScreener) Screen(context.Context, *tfmodules.ParsedModule) error {
	return f.screen
}

func TestChainResolverScreen(t *testing.T) {
	ctx := context.Background()
	mod := &tfmodules.ParsedModule{Name: "network", Source: "registry.example.com/network/aws"}
	denied := &tfmodules.UnresolvedError{Reason: `module host "registry.example.com" is not in --module-host-allowlist`}

	t.Run("screens a module out only when every resolver rules it out", func(t *testing.T) {
		err := NewChainResolver(
			fakeScreener{t: t, screen: notApplicable("not a local module")},
			fakeScreener{t: t, screen: denied},
		).Screen(ctx, mod)
		require.Equal(t, denied.Reason, unresolvedReason(t, err))
	})

	t.Run("keeps a module any resolver might resolve", func(t *testing.T) {
		require.NoError(t, NewChainResolver(
			fakeScreener{t: t, screen: denied},
			fakeScreener{t: t},
		).Screen(ctx, mod))
	})

	t.Run("keeps a module when a resolver cannot screen", func(t *testing.T) {
		require.NoError(t, NewChainResolver(
			fakeScreener{t: t, screen: denied},
			succeedingResolver("/modules/network"),
		).Screen(ctx, mod))
	})

	t.Run("reports declined reasons when nothing attempted the module", func(t *testing.T) {
		err := NewChainResolver(
			fakeScreener{t: t, screen: notApplicable("declined a")},
			fakeScreener{t: t, screen: notApplicable("declined b")},
		).Screen(ctx, mod)
		require.Equal(t, "declined a; declined b", unresolvedReason(t, err))
	})
}

func TestDefaultChainScreensHostsOutsideTheAllowlist(t *testing.T) {
	chain, err := NewDefaultChain(context.Background(), &DefaultChainConfig{
		FetchRemote:   true,
		HostAllowlist: []string{"registry.terraform.io", "github.com"},
		CacheRoot:     t.TempDir(),
	})
	require.NoError(t, err)

	privateRegistry := &tfmodules.ParsedModule{Name: "bucket", Source: "terraform-registry.example.io/team/bucket/aws"}
	err = chain.Screen(context.Background(), privateRegistry)
	require.Error(t, err)
	require.Equal(t, FailureAllowlistDenied, ClassifyFailure(err))

	allowedGit := &tfmodules.ParsedModule{Name: "vpc", Source: "git::https://github.com/acme/vpc.git?ref=v1"}
	require.NoError(t, chain.Screen(context.Background(), allowedGit))

	deniedGit := &tfmodules.ParsedModule{Name: "vpc", Source: "git::https://git.example.org/acme/vpc.git?ref=v1"}
	err = chain.Screen(context.Background(), deniedGit)
	require.Error(t, err)
	require.Equal(t, FailureAllowlistDenied, ClassifyFailure(err))
}
