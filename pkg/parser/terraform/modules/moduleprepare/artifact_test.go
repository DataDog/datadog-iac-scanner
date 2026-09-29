package moduleprepare

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/modulegraph"
	"github.com/stretchr/testify/require"
)

func TestMaterializerPruneRemovesOnlyUnreferencedPackages(t *testing.T) {
	packages := t.TempDir()
	kept := filepath.Join(packages, "kept")
	dropped := filepath.Join(packages, "dropped")
	writeFile(t, filepath.Join(kept, "main.tf"), `resource "aws_vpc" "kept" {}`)
	writeFile(t, filepath.Join(dropped, "main.tf"), `resource "aws_vpc" "dropped" {}`)

	artifact := t.TempDir()
	m, err := newMaterializer(t.Context(), artifact, t.TempDir(), []modulegraph.ResolvedModule{
		{PackageRoot: kept}, {PackageRoot: dropped},
	}, nil, false)
	require.NoError(t, err)
	keptPackage := m.packages[filepath.Clean(kept)]
	droppedPackage := m.packages[filepath.Clean(dropped)]
	require.DirExists(t, filepath.Join(artifact, manifestRoot, keptPackage.relativeRoot))
	require.DirExists(t, filepath.Join(artifact, manifestRoot, droppedPackage.relativeRoot))

	m.referenced[keptPackage.relativeRoot] = true
	require.NoError(t, m.prune())
	require.DirExists(t, filepath.Join(artifact, manifestRoot, keptPackage.relativeRoot))
	require.NoDirExists(t, filepath.Join(artifact, manifestRoot, droppedPackage.relativeRoot))
}

func TestMaterializerNeverLinksPackagesInsideTheRepository(t *testing.T) {
	repository := t.TempDir()
	inside := filepath.Join(repository, ".terraform", "modules", "vpc")
	writeFile(t, filepath.Join(inside, "main.tf"), `resource "aws_vpc" "this" {}`)
	outside := filepath.Join(t.TempDir(), "dns")
	writeFile(t, filepath.Join(outside, "main.tf"), `resource "aws_route53_zone" "this" {}`)

	artifact := t.TempDir()
	m, err := newMaterializer(t.Context(), artifact, repository, []modulegraph.ResolvedModule{
		{PackageRoot: inside}, {PackageRoot: outside},
	}, nil, true)
	require.NoError(t, err)

	sameFile := func(root string) bool {
		pkg := m.packages[filepath.Clean(root)]
		staged, statErr := os.Stat(filepath.Join(artifact, manifestRoot, pkg.relativeRoot, "main.tf"))
		require.NoError(t, statErr)
		source, statErr := os.Stat(filepath.Join(root, "main.tf"))
		require.NoError(t, statErr)
		return os.SameFile(staged, source)
	}
	require.False(t, sameFile(inside))
	require.True(t, sameFile(outside))
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(inside, "main.tf"))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o644), info.Mode().Perm())
	}
}

func TestStageFileFallsBackToCopyOnceLinkingFails(t *testing.T) {
	stager := &packageStager{packagesDir: t.TempDir()}
	destination := filepath.Join(stager.packagesDir, "copied.tf")
	missingSource := filepath.Join(t.TempDir(), "gone.tf")
	require.NoError(t, stager.stageFile(missingSource, destination, 0o644, strings.NewReader("content"), true))
	require.True(t, stager.linkFailed.Load())
	data, err := os.ReadFile(destination)
	require.NoError(t, err)
	require.Equal(t, "content", string(data))

	source := filepath.Join(t.TempDir(), "present.tf")
	require.NoError(t, os.WriteFile(source, []byte("other"), 0o644))
	second := filepath.Join(stager.packagesDir, "second.tf")
	require.NoError(t, stager.stageFile(source, second, 0o644, strings.NewReader("other"), true))
	sourceInfo, err := os.Stat(source)
	require.NoError(t, err)
	secondInfo, err := os.Stat(second)
	require.NoError(t, err)
	require.False(t, os.SameFile(sourceInfo, secondInfo), "linking stays off after a failure")
	if runtime.GOOS != "windows" {
		require.Equal(t, os.FileMode(0o640), secondInfo.Mode().Perm())
	}
}
