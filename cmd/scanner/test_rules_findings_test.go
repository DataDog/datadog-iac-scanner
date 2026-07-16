package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFindingsMatchMigratedFindingWithBackendExpectation(t *testing.T) {
	resourceType := "aws_iam_role"
	resourceName := "example"
	expected := ruleFinding{
		QueryName: "Example",
		Severity:  "HIGH",
		Line:      15,
		FileName:  "positive.json",
	}
	actual := ruleFinding{
		QueryName:    expected.QueryName,
		Severity:     expected.Severity,
		Line:         128,
		FileName:     expected.FileName,
		ResourceType: &resourceType,
		ResourceName: &resourceName,
	}

	require.True(t, findingsMatch(expected, actual))
}

func TestFindingsMatchUsesLineForResourceAwareExpectation(t *testing.T) {
	resourceType := "aws_iam_role"
	expected := ruleFinding{
		QueryName:    "Example",
		Severity:     "HIGH",
		Line:         15,
		FileName:     "positive.json",
		ResourceType: &resourceType,
	}
	actual := expected
	actual.Line = 128

	require.False(t, findingsMatch(expected, actual))
}

func TestParseFixtureFileIncludesCNIJSON(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "positive.json")
	require.NoError(t, os.WriteFile(
		path,
		[]byte(`{"name":"k8s-pod-network","cniVersion":"0.3.0","plugins":[{"type":"flannel"}]}`),
		0o600,
	))

	files, err := parseFixtureFile(context.Background(), root, path, "Kubernetes")

	require.NoError(t, err)
	require.Len(t, files, 1)
	require.Equal(t, "0.3.0", files[0].Document["cniVersion"])
}
