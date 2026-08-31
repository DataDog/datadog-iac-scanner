package moduleprepare

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/modulegraph"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
	"github.com/stretchr/testify/require"
)

func TestWriteResultEmitsGenericCallScopedRequestsWithoutManifest(t *testing.T) {
	repositoryRoot := t.TempDir()
	callerA := filepath.Join(repositoryRoot, "a", "main.tf")
	callerB := filepath.Join(repositoryRoot, "b", "main.tf")
	require.NoError(t, os.MkdirAll(filepath.Dir(callerA), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Dir(callerB), 0o755))
	require.NoError(t, os.WriteFile(callerA, []byte("module"), 0o600))
	require.NoError(t, os.WriteFile(callerB, []byte("module"), 0o600))

	moduleRoot := t.TempDir()
	responsePath := filepath.Join(moduleRoot, "response.json")
	manifestPath := filepath.Join(moduleRoot, "manifest.json")
	require.NoError(t, os.WriteFile(manifestPath, []byte("stale"), 0o600))
	source := "terraform-aws-modules/vpc/aws"
	result := modulegraph.Result{
		Failures: []modulegraph.ResolutionFailure{
			{
				RequestID:     resolver.ModuleCallID(callerA, 1, 3, "vpc_a", source, ""),
				CallerFile:    callerA,
				CallerLine:    1,
				CallerEndLine: 3,
				Source:        source,
				Name:          "vpc_a",
				Reason:        "not found in staged modules",
			},
			{
				RequestID:     resolver.ModuleCallID(callerB, 1, 3, "vpc_b", source, ""),
				CallerFile:    callerB,
				CallerLine:    1,
				CallerEndLine: 3,
				Source:        source,
				Name:          "vpc_b",
				Reason:        "not found in staged modules",
			},
		},
	}

	response, err := WriteResult(
		t.Context(),
		responsePath,
		manifestPath,
		moduleRoot,
		[]string{repositoryRoot},
		&result,
		10,
	)
	require.NoError(t, err)
	require.Equal(t, StatusRequiresStaging, response.Status)
	require.Empty(t, response.ManifestPath)
	require.Len(t, response.Requests, 2)
	require.NotEqual(t, response.Requests[0].RequestID, response.Requests[1].RequestID)
	require.Equal(t, response.Requests[0].AcquisitionKey, response.Requests[1].AcquisitionKey)
	_, err = os.Stat(manifestPath)
	require.ErrorIs(t, err, os.ErrNotExist)

	data, err := os.ReadFile(responsePath)
	require.NoError(t, err)
	var persisted Response
	require.NoError(t, json.Unmarshal(data, &persisted))
	require.Equal(t, response.Status, persisted.Status)
	require.Equal(t, response.Modules, persisted.Modules)
	require.Equal(t, response.Requests, persisted.Requests)
}

func TestWriteResultPublishesManifestOnlyWhenComplete(t *testing.T) {
	repositoryRoot := t.TempDir()
	caller := filepath.Join(repositoryRoot, "main.tf")
	require.NoError(t, os.WriteFile(caller, []byte("module"), 0o600))
	moduleRoot := t.TempDir()
	packageRoot := filepath.Join(moduleRoot, "packages", "module")
	require.NoError(t, os.MkdirAll(packageRoot, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(packageRoot, "main.tf"), []byte("resource"), 0o600))
	source := "terraform-aws-modules/vpc/aws"
	requestID := resolver.ModuleCallID(caller, 1, 3, "vpc", source, "~> 5.0")
	result := modulegraph.Result{
		Modules: []modulegraph.ResolvedModule{{
			RequestID:       requestID,
			CallerFile:      caller,
			CallerLine:      1,
			CallerEndLine:   3,
			Source:          source,
			Version:         "~> 5.0",
			ResolvedVersion: "5.4.0",
			Name:            "vpc",
			LocalPath:       packageRoot,
			PackageRoot:     packageRoot,
		}},
	}
	responsePath := filepath.Join(moduleRoot, "response.json")
	manifestPath := filepath.Join(moduleRoot, "manifest.json")

	response, err := WriteResult(
		t.Context(),
		responsePath,
		manifestPath,
		moduleRoot,
		[]string{repositoryRoot},
		&result,
		10,
	)
	require.NoError(t, err)
	require.Equal(t, StatusComplete, response.Status)
	require.Equal(t, filepath.ToSlash(manifestPath), response.ManifestPath)
	manifest, err := resolver.LoadManifest(t.Context(), manifestPath)
	require.NoError(t, err)
	require.Contains(t, manifest.Modules, requestID)
}

func TestWriteResultBoundsBudgetEvents(t *testing.T) {
	moduleRoot := t.TempDir()
	result := modulegraph.Result{
		BudgetEvents: []modulegraph.BudgetEvent{
			{Source: "a", Gate: "graph", Limit: "module_count", Maximum: 1, Measured: 2},
			{Source: "b", Gate: "graph", Limit: "module_count", Maximum: 1, Measured: 3},
			{Source: "c", Gate: "graph", Limit: "module_count", Maximum: 1, Measured: 4},
		},
	}
	response, err := WriteResult(
		t.Context(),
		filepath.Join(moduleRoot, "response.json"),
		filepath.Join(moduleRoot, "manifest.json"),
		moduleRoot,
		nil,
		&result,
		2,
	)
	require.NoError(t, err)
	require.Equal(t, StatusIncomplete, response.Status)
	require.Len(t, response.Termination.BudgetEvents, 2)
	require.Equal(t, 1, response.Termination.OmittedBudgetEvents)
}
