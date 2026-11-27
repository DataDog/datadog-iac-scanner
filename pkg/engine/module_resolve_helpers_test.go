/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

// resolveModuleDocumentsForTest is resolveModuleDocuments for a scan without
// inventory.
func resolveModuleDocumentsForTest(
	ctx context.Context,
	files model.FileMetadatas,
	repoPath string,
	resolver tfeval.RemoteResolver,
	targets *ruleTargets,
	lookup moduleProvenanceLookup,
	mergeAllow map[string]struct{},
	fsys vfs.FS,
	externalModuleFile func(string) bool,
) moduleResolutionResult {
	return resolveModuleDocuments(ctx, files, repoPath, resolver, targets, lookup, mergeAllow, fsys, externalModuleFile, nil, nil, nil, false, nil)
}
