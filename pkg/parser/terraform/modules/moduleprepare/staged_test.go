package moduleprepare

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
	"github.com/stretchr/testify/require"
)

func TestWriteStagedManifestExtractsAndVerifiesArchive(t *testing.T) {
	moduleRoot := t.TempDir()
	archivePath := filepath.Join(moduleRoot, "incoming", "module.zip")
	writeZip(t, archivePath, map[string]string{
		"module-commit/modules/vpc/main.tf": `resource "test" "vpc" {}`,
	})
	digest := fileSHA256(t, archivePath)
	caller := filepath.Join(t.TempDir(), "main.tf")
	source := "git::https://github.com/acme/module.git//modules/vpc?ref=v1"
	requestID := resolver.ModuleCallID(caller, 1, 3, "vpc", source, "")
	inputPath := writeStagedInput(t, moduleRoot, StagedModules{
		SchemaVersion: ResponseSchemaVersion,
		Modules: []StagedModule{{
			RequestID:       requestID,
			Source:          source,
			ResolvedRef:     "0123456789012345678901234567890123456789",
			Kind:            StagedKindArchive,
			ArtifactPath:    "incoming/module.zip",
			ArchiveFormat:   "zip",
			TransportDigest: digest,
			Declarations: []resolver.ManifestDeclaration{{
				Filename:   "main.tf",
				LineStart:  1,
				LineEnd:    3,
				ModuleName: "vpc",
			}},
		}},
	})
	manifestPath := filepath.Join(moduleRoot, "staged.json")

	err := WriteStagedManifest(t.Context(), inputPath, manifestPath, moduleRoot, testLimits())
	require.NoError(t, err)
	manifest, err := resolver.LoadManifest(t.Context(), manifestPath)
	require.NoError(t, err)
	resolution, err := resolver.NewPrefetchedResolver(manifest).Resolve(
		t.Context(),
		&tfmodules.ParsedModule{
			FileName:   caller,
			DefLine:    1,
			DefEndLine: 3,
			Name:       "vpc",
			Source:     source,
		},
	)
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(resolution.LocalPath, "main.tf"))
	require.Equal(t, "0123456789012345678901234567890123456789", resolution.ResolvedRef)
}

func TestWriteStagedManifestRejectsTransportDigestMismatch(t *testing.T) {
	moduleRoot := t.TempDir()
	archivePath := filepath.Join(moduleRoot, "module.zip")
	writeZip(t, archivePath, map[string]string{"main.tf": "resource"})
	inputPath := writeStagedInput(t, moduleRoot, StagedModules{
		SchemaVersion: ResponseSchemaVersion,
		Modules: []StagedModule{{
			RequestID:       "request",
			Source:          "terraform-aws-modules/vpc/aws",
			Kind:            StagedKindArchive,
			ArtifactPath:    "module.zip",
			ArchiveFormat:   "zip",
			TransportDigest: "sha256:" + strings.Repeat("0", 64),
			Declarations: []resolver.ManifestDeclaration{{
				Filename:   "main.tf",
				LineStart:  1,
				LineEnd:    3,
				ModuleName: "vpc",
			}},
		}},
	})

	err := WriteStagedManifest(
		t.Context(),
		inputPath,
		filepath.Join(moduleRoot, "manifest.json"),
		moduleRoot,
		testLimits(),
	)
	require.ErrorContains(t, err, "transport_digest mismatch")
}

func TestWriteStagedManifestPreservesDuplicateUnversionedCalls(t *testing.T) {
	moduleRoot := t.TempDir()
	packagePath := filepath.Join(moduleRoot, "packages", "shared")
	require.NoError(t, os.MkdirAll(packagePath, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(packagePath, "main.tf"), []byte("resource"), 0o600))
	source := "terraform-aws-modules/vpc/aws"
	first := &tfmodules.ParsedModule{
		FileName:   filepath.Join("/workspace", "a", "main.tf"),
		DefLine:    1,
		DefEndLine: 3,
		Name:       "vpc_a",
		Source:     source,
	}
	second := &tfmodules.ParsedModule{
		FileName:   filepath.Join("/workspace", "b", "main.tf"),
		DefLine:    1,
		DefEndLine: 3,
		Name:       "vpc_b",
		Source:     source,
	}
	inputPath := writeStagedInput(t, moduleRoot, StagedModules{
		SchemaVersion: ResponseSchemaVersion,
		Modules: []StagedModule{
			stagedDirectory(first, "packages/shared"),
			stagedDirectory(second, "packages/shared"),
		},
	})
	manifestPath := filepath.Join(moduleRoot, "manifest.json")

	require.NoError(t, WriteStagedManifest(
		t.Context(),
		inputPath,
		manifestPath,
		moduleRoot,
		testLimits(),
	))
	manifest, err := resolver.LoadManifest(t.Context(), manifestPath)
	require.NoError(t, err)
	require.Len(t, manifest.Modules, 2)
	for _, module := range []*tfmodules.ParsedModule{first, second} {
		_, err := resolver.NewPrefetchedResolver(manifest).Resolve(t.Context(), module)
		require.NoError(t, err)
	}
}

func TestWriteStagedManifestEnforcesFileLimitForDirectory(t *testing.T) {
	moduleRoot := t.TempDir()
	packagePath := filepath.Join(moduleRoot, "package")
	require.NoError(t, os.MkdirAll(packagePath, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(packagePath, "main.tf"), []byte("content"), 0o600))
	module := &tfmodules.ParsedModule{
		FileName:   filepath.Join("/workspace", "main.tf"),
		DefLine:    1,
		DefEndLine: 3,
		Name:       "vpc",
		Source:     "terraform-aws-modules/vpc/aws",
	}
	inputPath := writeStagedInput(t, moduleRoot, StagedModules{
		SchemaVersion: ResponseSchemaVersion,
		Modules:       []StagedModule{stagedDirectory(module, "package")},
	})
	limits := testLimits()
	limits.MaxFileBytes = 3

	err := WriteStagedManifest(
		t.Context(),
		inputPath,
		filepath.Join(moduleRoot, "manifest.json"),
		moduleRoot,
		limits,
	)
	var budgetErr *resolver.BudgetExceededError
	require.ErrorAs(t, err, &budgetErr)
	require.Equal(t, "file_bytes", budgetErr.Limit)
}

func TestWriteStagedManifestRejectsArchiveEscape(t *testing.T) {
	moduleRoot := t.TempDir()
	archivePath := filepath.Join(moduleRoot, "module.zip")
	writeZip(t, archivePath, map[string]string{"../outside.tf": "content"})
	inputPath := writeStagedInput(t, moduleRoot, StagedModules{
		SchemaVersion: ResponseSchemaVersion,
		Modules: []StagedModule{{
			RequestID:       "request",
			Source:          "terraform-aws-modules/vpc/aws",
			Kind:            StagedKindArchive,
			ArtifactPath:    "module.zip",
			ArchiveFormat:   "zip",
			TransportDigest: fileSHA256(t, archivePath),
			Declarations: []resolver.ManifestDeclaration{{
				Filename:   "main.tf",
				LineStart:  1,
				LineEnd:    3,
				ModuleName: "vpc",
			}},
		}},
	})

	err := WriteStagedManifest(
		t.Context(),
		inputPath,
		filepath.Join(moduleRoot, "manifest.json"),
		moduleRoot,
		testLimits(),
	)
	require.ErrorContains(t, err, "not a local path")
	require.NoFileExists(t, filepath.Join(filepath.Dir(moduleRoot), "outside.tf"))
}

func stagedDirectory(module *tfmodules.ParsedModule, packagePath string) StagedModule {
	return StagedModule{
		RequestID:   resolver.ParsedModuleCallID(module),
		Source:      module.Source,
		Kind:        StagedKindDirectory,
		PackagePath: packagePath,
		Declarations: []resolver.ManifestDeclaration{{
			Filename:   filepath.Base(module.FileName),
			LineStart:  module.DefLine,
			LineEnd:    module.DefEndLine,
			ModuleName: module.Name,
		}},
	}
}

func testLimits() resolver.ResourceLimits {
	return resolver.ResourceLimits{
		MaxPackageBytes: 1024 * 1024,
		MaxFileBytes:    1024 * 1024,
		MaxPackageFiles: 100,
	}
}

func writeStagedInput(t *testing.T, root string, input StagedModules) string {
	t.Helper()
	data, err := json.Marshal(input)
	require.NoError(t, err)
	path := filepath.Join(root, "staged-input.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func writeZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	file, err := os.Create(path)
	require.NoError(t, err)
	writer := zip.NewWriter(file)
	for name, content := range files {
		entry, err := writer.Create(name)
		require.NoError(t, err)
		_, err = entry.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, writer.Close())
	require.NoError(t, file.Close())
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
