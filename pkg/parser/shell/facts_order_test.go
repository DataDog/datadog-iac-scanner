package shell

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFactsSuccessPredecessors(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   [][]int
	}{
		{
			name:   "and chain is transitive",
			script: "apt-get update && apt-get install curl && rm -rf /var/lib/apt/lists/*",
			want:   [][]int{nil, {0}, {0, 1}},
		},
		{
			name:   "ordinary sequencing does not require success",
			script: "apt-get update; apt-get install curl",
			want:   [][]int{nil, nil},
		},
		{
			name:   "failure branch is not a success predecessor",
			script: "apt-get update || apt-get install curl",
			want:   [][]int{nil, nil},
		},
		{
			name:   "success branch after a failure branch only depends on the success guard",
			script: "apt-get update || apt-get install curl && rm -rf /var/lib/apt/lists/*",
			// The status of the `||` compound list cannot be attributed to
			// either command, so it must not create an `&&` success edge.
			want: [][]int{nil, nil, nil},
		},
		{
			name:   "pipeline stages are isolated",
			script: "apt-get update | cat && apt-get install curl",
			want:   [][]int{nil, nil, nil},
		},
		{
			name:   "and chain inside conditional retains its success relation",
			script: "if true; then apt-get update && apt-get install curl; fi",
			want:   [][]int{nil, nil, {1}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			facts := Analyze(tc.script, "sh")
			require.True(t, facts.Complete, facts.Diagnostics)
			require.Len(t, facts.Calls, len(tc.want))
			for i, predecessors := range tc.want {
				require.Equal(t, predecessors, facts.Calls[i].SuccessPredecessors, "call %d", i)
			}
		})
	}
}

func TestFactsOrderedPredecessors(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		want         [][]int
	}{
		{
			name:   "ordinary sequential cleanup is ordered",
			script: "apk add curl; rm -rf /var/cache/apk/*",
			want:   [][]int{nil, {0}},
		},
		{
			name:   "mutually exclusive conditional branches are not ordered",
			script: "if true; then apk add curl; else echo skip; fi",
			want:   [][]int{nil, nil, nil},
		},
		{
			name:   "success edge inside a conditional is ordered",
			script: "if true; then apk add curl && rm -rf /var/cache/apk/*; fi",
			want:   [][]int{nil, nil, {1}},
		},
		{
			name:   "pipeline calls are not ordered",
			script: "apk add curl | cat; rm -rf /var/cache/apk/*",
			want:   [][]int{nil, nil, nil},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := Analyze(tc.script, "sh")
			require.True(t, facts.Complete, facts.Diagnostics)
			require.Len(t, facts.Calls, len(tc.want))
			for i, predecessors := range tc.want {
				require.Equal(t, predecessors, facts.Calls[i].OrderedPredecessors, "call %d", i)
			}
		})
	}
}

func TestFactsPackageCleanupChainsAreOrdered(t *testing.T) {
	for _, tc := range []struct {
		name, script, manager, cleanup string
	}{
		{"apt chain and list removal", "apt-get install -y curl && apt-get clean && rm -rf /var/lib/apt/lists/*", "apt-get", "rm"},
		{"dnf chain after setup", "dnf config-manager --set-enabled repo && sed -i 's/a/b/' /etc/config && dnf install -y curl && dnf clean all", "dnf", "dnf"},
		{"zypper install then clean", "zypper install -y httpd=2.4 && zypper clean", "zypper", "zypper"},
		{"yum install then clean", "yum install -y curl && yum clean all", "yum", "yum"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := Analyze(tc.script, "sh")
			require.True(t, facts.Complete, facts.Diagnostics)
			var installCall, cleanupCall = -1, -1
			for _, command := range facts.PackageCommands {
				if command.Manager == tc.manager && command.Action == "install" {
					installCall = command.Call
				}
			}
			for i, call := range facts.Calls {
				if call.Name != tc.cleanup || len(call.Arguments) == 0 {
					continue
				}
				if tc.cleanup == "rm" || call.Arguments[0].Text == "clean" {
					cleanupCall = i
				}
			}
			require.NotEqual(t, -1, installCall, "install call is present: %#v", facts.PackageCommands)
			require.NotEqual(t, -1, cleanupCall, "cleanup call is present: %#v", facts.Calls)
			require.Contains(t, facts.Calls[cleanupCall].OrderedPredecessors, installCall,
				"cleanup call must retain the install call as a proven predecessor")
		})
	}
}

func TestFactsOrderingBudgetMarksLargeRelationIncomplete(t *testing.T) {
	facts := Analyze(strings.Repeat("echo x; ", 1000), "sh")
	require.False(t, facts.Complete)
	require.Contains(t, facts.Diagnostics, "command ordering analysis limit reached")
	require.Len(t, facts.Calls, 1000, "known calls survive when relation expansion reaches its budget")
	require.Equal(t, "echo", facts.Calls[0].Name)
	require.Equal(t, "echo", facts.Calls[len(facts.Calls)-1].Name)
	for i := range facts.Calls {
		require.Empty(t, facts.Calls[i].SuccessPredecessors, "partial success edges must be cleared")
		require.Empty(t, facts.Calls[i].OrderedPredecessors, "partial order edges must be cleared")
	}
}
