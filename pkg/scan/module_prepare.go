/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package scan

import (
	"context"
	"fmt"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/modulegraph"
	tfresolver "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

func PrepareTerraformModules(
	ctx context.Context,
	params *Parameters,
	rootPaths []string,
	discoveryPaths []string,
) (modulegraph.Result, error) {
	if params == nil {
		return modulegraph.Result{}, fmt.Errorf("scan parameters are required")
	}
	if !params.NetworkIsolation {
		return modulegraph.Result{}, fmt.Errorf("module preparation requires network isolation")
	}
	client := &Client{
		ScanParams: params,
		fsys:       vfs.DiskFS{},
	}
	resolveCtx, cancel := client.moduleResolutionContext(ctx)
	defer cancel()
	resolvers := []tfresolver.Resolver{tfresolver.LocalResolver{}}
	if params.RemoteModulesManifestPath != "" {
		manifest, err := tfresolver.LoadManifest(resolveCtx, params.RemoteModulesManifestPath)
		if err != nil {
			return modulegraph.Result{}, err
		}
		resolvers = append(resolvers, tfresolver.NewPrefetchedResolver(manifest))
	}
	chain := tfresolver.NewChainResolver(resolvers...)
	return client.resolveTerraformModuleGraph(resolveCtx, rootPaths, discoveryPaths, nil, chain), nil
}
