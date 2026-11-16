/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"context"
	"path/filepath"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/comment"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// parseTerragrunt parses a Terragrunt file into one empty document: rules run
// on the modules units call, never on the file itself. The file is still
// scanned so its ignore comments apply to findings attributed to it.
func parseTerragrunt(ctx context.Context, content []byte, path string) (
	resolved []byte,
	documents []model.Document,
	ignoreLines []int,
	resolvedFiles map[string]model.ResolvedFile,
	err error,
) {
	file, diags := hclsyntax.ParseConfig(content, filepath.Base(path), hcl.Pos{Byte: 0, Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, nil, nil, nil, diags.Errs()[0]
	}
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return content, []model.Document{{}}, nil, nil, nil
	}
	ignore, commentErr := comment.ParseComments(content, path)
	if commentErr != nil {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Err(commentErr).Msgf("failed to parse comments of %s", path)
	}
	return content, []model.Document{{}}, comment.GetIgnoreLines(ignore, body), nil, nil
}
