/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfharness

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/console"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/scan"
)

// scanTo runs a whole scan of dir the way the command line does, with the
// probe rules and the shared libraries, writing its reports into out.
func scanTo(t *testing.T, dir, rulesDir, librariesPath, out string) {
	t.Helper()
	params, ctx := scan.GetDefaultParameters(context.Background(), "")
	params.Path = []string{dir}
	params.OutputPath = out
	params.OutputName = "result"
	params.QueriesPath = []string{rulesDir}
	params.ChangedDefaultQueryPath = true
	params.LibrariesPath = librariesPath
	params.ChangedDefaultLibrariesPath = true
	params.Platform = []string{"Terraform"}
	params.SCIInfo = model.SCIInfo{
		DiffAware:            model.DiffAware{Enabled: false},
		RepositoryCommitInfo: model.RepositoryCommitInfo{RepositoryUrl: "test/url", CommitSHA: "test/hash", Branch: "test/branch"},
	}
	params.FlagEvaluator = featureflags.NewLocalEvaluator()
	if _, err := console.ExecuteScan(ctx, params); err != nil {
		t.Fatal(err)
	}
}

// LibraryPath is the shared Terraform and common Rego library the probe
// rules and the end-to-end fixtures use, found through this package's own
// location in the repository.
func LibraryPath(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the harness source")
	}
	return filepath.Join(filepath.Dir(file), "..", "e2e", "testdata", "terraform_rules", "libraries")
}
