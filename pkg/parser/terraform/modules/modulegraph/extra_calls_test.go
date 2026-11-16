/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package modulegraph

import (
	"os"
	"path/filepath"
	"testing"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
	"github.com/stretchr/testify/require"
)

// Calls declared outside Terraform files (Terragrunt units) are fetched like
// root calls, with the declaring file's directory as caller root, and the
// modules they call are fetched too.
func TestResolveExtraCalls(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	unitDir := filepath.Join(base, "live", "prod")
	vpc := filepath.Join(base, "cache", "vpc")
	subnets := filepath.Join(base, "cache", "subnets")
	for _, dir := range []string{unitDir, vpc, subnets} {
		require.NoError(t, os.MkdirAll(dir, 0o755))
	}
	unitFile := filepath.Join(unitDir, "terragrunt.hcl")
	require.NoError(t, os.WriteFile(unitFile, []byte(`terraform { source = "tfr:///acme/vpc/aws?version=1.0.0" }`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(vpc, "main.tf"), []byte(`
resource "aws_vpc" "this" {}
module "subnets" {
  source = "example.com/acme/subnets/aws"
}
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(subnets, "main.tf"), []byte(`resource "aws_subnet" "this" {}`), 0o600))

	result := Resolve(t.Context(), &Request{
		RootPaths: []string{base},
		Resolver: mapResolver{bySource: map[string]resolver.Resolution{
			"acme/vpc/aws":                 {LocalPath: vpc, PackageRoot: vpc},
			"example.com/acme/subnets/aws": {LocalPath: subnets, PackageRoot: subnets},
		}},
		MaxDepth: 3,
		ExtraCalls: []tfmodules.ParsedModule{
			{Name: "terragrunt", Source: "acme/vpc/aws", Version: "1.0.0", SourceType: "registry", FileName: unitFile},
			{Name: "local", Source: "../modules/x", IsLocal: true, FileName: unitFile},
			{Name: "empty", FileName: unitFile},
		},
	})

	bySource := map[string]ResolvedModule{}
	for _, module := range result.Modules {
		bySource[module.Source] = module
	}
	require.Len(t, bySource, 2)
	require.Equal(t, unitDir, bySource["acme/vpc/aws"].CallerRoot)
	require.Equal(t, "terragrunt", bySource["acme/vpc/aws"].Name)
	require.Equal(t, "1.0.0", bySource["acme/vpc/aws"].Version)
	require.Equal(t, vpc, bySource["acme/vpc/aws"].LocalPath)
	require.Equal(t, subnets, bySource["example.com/acme/subnets/aws"].LocalPath)
	require.ElementsMatch(t, []string{filepath.Join(vpc, "main.tf"), filepath.Join(subnets, "main.tf")}, result.ScanPaths)
}
