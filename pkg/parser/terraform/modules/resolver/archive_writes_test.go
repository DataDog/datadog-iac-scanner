/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSparseArchiveDiscard(t *testing.T) {
	const sha = "0123456789abcdef0123456789abcdef01234567"
	setup := func(t *testing.T) (*sparseArchive, string, string) {
		t.Helper()
		extractBase := t.TempDir()
		dest := archiveCacheDir(extractBase, sha)
		stateRoot := filepath.Dir(archiveMarkerPath(extractBase, sha, "."))
		require.NoError(t, os.MkdirAll(filepath.Join(dest, "existing"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dest, "existing", "main.tf"), []byte("# kept"), 0o600))
		require.NoError(t, os.MkdirAll(stateRoot, 0o755))
		storeArchiveUsage(dest, PackageUsage{Files: 2, Bytes: 6})
		t.Cleanup(func() { forgetArchiveUsage(dest) })

		archive := &sparseArchive{sha: sha, dest: dest, extractBase: extractBase}
		created := filepath.Join(dest, "created")
		require.NoError(t, archive.written.mkdirAll(created))
		file := filepath.Join(created, "main.tf")
		archive.written.addFile(file, 3)
		require.NoError(t, os.WriteFile(file, []byte("new"), 0o600))
		return archive, dest, stateRoot
	}

	t.Run("successful rollback keeps the shared tree", func(t *testing.T) {
		archive, dest, stateRoot := setup(t)
		archive.discard()

		require.NoDirExists(t, filepath.Join(dest, "created"))
		require.FileExists(t, filepath.Join(dest, "existing", "main.tf"))
		require.DirExists(t, stateRoot)
		_, known := knownArchiveUsage(dest)
		require.True(t, known)
	})

	t.Run("failed rollback keeps the shared tree and forgets its usage", func(t *testing.T) {
		archive, dest, stateRoot := setup(t)
		// A file nobody recorded keeps the created directory from being removed.
		require.NoError(t, os.WriteFile(filepath.Join(dest, "created", "foreign.tf"), nil, 0o600))
		archive.discard()

		require.FileExists(t, filepath.Join(dest, "existing", "main.tf"), "other modules still read the tree")
		require.NoFileExists(t, filepath.Join(dest, "created", "main.tf"))
		require.DirExists(t, stateRoot)
		_, known := knownArchiveUsage(dest)
		require.False(t, known)
	})

	t.Run("a marker that cannot be removed keeps the files it covers", func(t *testing.T) {
		archive, dest, _ := setup(t)
		marker := archiveMarkerPath(archive.extractBase, sha, "created")
		archive.markers.addFile(marker, 0)
		// A non-empty directory where the marker was recorded cannot be removed.
		require.NoError(t, os.MkdirAll(filepath.Join(marker, "stuck"), 0o755))
		archive.discard()

		require.FileExists(t, filepath.Join(dest, "created", "main.tf"))
		_, known := knownArchiveUsage(dest)
		require.False(t, known)
	})
}

func TestArchiveWritesRollbackRemovesOnlyCreatedPaths(t *testing.T) {
	root := t.TempDir()
	existing := filepath.Join(root, "modules", "existing.tf")
	require.NoError(t, os.MkdirAll(filepath.Dir(existing), 0o750))
	require.NoError(t, os.WriteFile(existing, []byte("keep"), 0o600))

	writes := &archiveWrites{}
	created := filepath.Join(root, "modules", "vpc", "nested", "main.tf")
	require.NoError(t, writes.mkdirAll(filepath.Dir(created)))
	writes.addFile(created, 3)
	require.NoError(t, os.WriteFile(created, []byte("new"), 0o600))
	require.Equal(t, PackageUsage{Bytes: 3, Files: 3}, writes.usage)

	require.NoError(t, writes.rollback())
	_, err := os.Stat(filepath.Join(root, "modules", "vpc"))
	require.True(t, os.IsNotExist(err), "created directories remain: %v", err)
	data, err := os.ReadFile(existing)
	require.NoError(t, err)
	require.Equal(t, "keep", string(data))
}

func writeArchiveModuleRepo(t *testing.T) (gitDir, sha string) {
	t.Helper()
	workTree := t.TempDir()
	runGit(t, workTree, "init", "-q", "-b", "main")
	modules := map[string]string{
		"selected": "module \"shared\" { source = \"../shared\" }\n",
		"shared":   "# shared\n",
		"other":    "# other\n",
	}
	for module, content := range modules {
		dir := filepath.Join(workTree, "modules", module)
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(content), 0o644))
	}
	runGit(t, workTree, "add", ".")
	runGit(t, workTree, "commit", "-q", "-m", "modules")
	return filepath.Join(workTree, ".git"), runGit(t, workTree, "rev-parse", "HEAD")
}

func TestArchiveExtractRecordsExactPackageUsage(t *testing.T) {
	gitDir, sha := writeArchiveModuleRepo(t)
	extractBase := t.TempDir()
	packageRoot := archiveCacheDir(extractBase, sha)

	var written int64
	for _, subdir := range []string{"modules/selected", "modules/other", "modules/selected"} {
		n, err := archiveExtract(
			t.Context(), gitDir, extractBase, sha, subdir, localCloneArchiveCommand(gitDir), nil,
		)
		require.NoError(t, err)
		written += n
		measured, err := MeasurePackage(t.Context(), packageRoot, ResourceLimits{})
		require.NoError(t, err)
		recorded, ok := knownArchiveUsage(packageRoot)
		require.True(t, ok)
		require.Equal(t, measured, recorded, "after extracting %s", subdir)
		require.Equal(t, directorySize(extractBase), written, "bytes reported after extracting %s", subdir)
	}
}

func TestArchiveExtractFailureRemovesOnlyItsOwnWrites(t *testing.T) {
	gitDir, sha := writeArchiveModuleRepo(t)
	extractBase := t.TempDir()
	packageRoot := archiveCacheDir(extractBase, sha)
	_, err := archiveExtract(
		t.Context(), gitDir, extractBase, sha, "modules/shared", localCloneArchiveCommand(gitDir), nil,
	)
	require.NoError(t, err)
	before, ok := knownArchiveUsage(packageRoot)
	require.True(t, ok)

	// Room for the archive's pax header and the new directory, but not its file.
	limits := ResourceLimits{MaxPackageFiles: before.Files + 2}
	ctx := WithResourceBudget(t.Context(), NewResourceBudget(limits))
	_, err = archiveExtract(ctx, gitDir, extractBase, sha, "modules/selected", localCloneArchiveCommand(gitDir), nil)
	var budgetErr *BudgetExceededError
	require.ErrorAs(t, err, &budgetErr)

	_, statErr := os.Stat(filepath.Join(packageRoot, "modules", "selected"))
	require.True(t, os.IsNotExist(statErr), "failed extraction left files behind: %v", statErr)
	_, statErr = os.Stat(archiveMarkerPath(extractBase, sha, "modules/selected"))
	require.True(t, os.IsNotExist(statErr), "failed extraction left a marker: %v", statErr)
	_, ok = cachedArchiveDir(extractBase, sha, "modules/shared")
	require.True(t, ok)
	measured, err := MeasurePackage(t.Context(), packageRoot, ResourceLimits{})
	require.NoError(t, err)
	require.Equal(t, before, measured)
	recorded, ok := knownArchiveUsage(packageRoot)
	require.True(t, ok)
	require.Equal(t, before, recorded)
}

func TestIsShallowUnsupportedMessage(t *testing.T) {
	require.True(t, isShallowUnsupportedMessage("fatal: dumb http transport does not support shallow capabilities"))
	require.True(t, isShallowUnsupportedMessage("error: Server does not allow request for unadvertised object"))
	require.False(t, isShallowUnsupportedMessage("fatal: couldn't find remote ref v9.9.9"))
	require.False(t, isShallowUnsupportedMessage("fatal: Authentication failed"))
}
