/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type tarEntry struct {
	name     string
	typeflag byte
	body     string
	linkname string
}

func extractTestArchive(r *bytes.Reader, dest string) error {
	extracted := int64(0)
	return extractRegularFilesWithResourceBudget(r, dest, &extracted, nil, nil)
}

func tarBytes(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, entry := range entries {
		require.NoError(t, writer.WriteHeader(&tar.Header{
			Name:     entry.name,
			Typeflag: entry.typeflag,
			Mode:     0o644,
			Size:     int64(len(entry.body)),
			Linkname: entry.linkname,
		}))
		if entry.body != "" {
			_, err := writer.Write([]byte(entry.body))
			require.NoError(t, err)
		}
	}
	require.NoError(t, writer.Close())
	return buffer.Bytes()
}

func TestExtractRegularFiles(t *testing.T) {
	dest := t.TempDir()
	archive := tarBytes(t,
		tarEntry{name: "modules/", typeflag: tar.TypeDir},
		tarEntry{name: "modules/vpc/main.tf", typeflag: tar.TypeReg, body: `resource "x" "y" {}`},
	)

	require.NoError(t, extractTestArchive(bytes.NewReader(archive), dest))
	data, err := os.ReadFile(filepath.Join(dest, "modules", "vpc", "main.tf"))
	require.NoError(t, err)
	require.Equal(t, `resource "x" "y" {}`, string(data))
}

func TestExtractRegularFilesSkipsNonRegularEntries(t *testing.T) {
	dest := t.TempDir()
	archive := tarBytes(t,
		tarEntry{name: "main.tf", typeflag: tar.TypeReg, body: `resource "x" "y" {}`},
		tarEntry{name: "linked.tf", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
		tarEntry{name: "hard.tf", typeflag: tar.TypeLink, linkname: "main.tf"},
		tarEntry{name: "dev.tf", typeflag: tar.TypeChar},
	)

	require.NoError(t, extractTestArchive(bytes.NewReader(archive), dest))
	_, err := os.Lstat(filepath.Join(dest, "linked.tf"))
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Lstat(filepath.Join(dest, "hard.tf"))
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.ReadFile(filepath.Join(dest, "main.tf"))
	require.NoError(t, err)
}

func TestExtractRegularFilesRejectsEscapingPaths(t *testing.T) {
	parent := t.TempDir()
	dest := filepath.Join(parent, "extract")
	require.NoError(t, os.Mkdir(dest, 0o755))

	for _, name := range []string{"../outside.tf", "modules/../../outside.tf", "/absolute.tf"} {
		t.Run(name, func(t *testing.T) {
			archive := tarBytes(t, tarEntry{name: name, typeflag: tar.TypeReg, body: "content"})
			require.ErrorContains(t, extractTestArchive(bytes.NewReader(archive), dest), "is not a local path")
			_, err := os.Stat(filepath.Join(parent, "outside.tf"))
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

func TestExtractRegularFilesEnforcesResourceBudgetBeforeWrite(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		limits ResourceLimits
	}{
		{name: "file size", limits: ResourceLimits{MaxFileBytes: 3}},
		{name: "package size", limits: ResourceLimits{MaxPackageBytes: 3}},
		{name: "file count", limits: ResourceLimits{MaxPackageFiles: 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			archive := tarBytes(t, tarEntry{name: "main.tf", typeflag: tar.TypeReg, body: "content"})
			counter := NewResourceBudget(tt.limits).NewPackageCounter()
			if tt.name == "file count" {
				counter = NewResourceBudget(ResourceLimits{MaxPackageFiles: 1}).NewPackageCounter()
				archive = tarBytes(t,
					tarEntry{name: "one.tf", typeflag: tar.TypeReg, body: "a"},
					tarEntry{name: "two.tf", typeflag: tar.TypeReg, body: "b"},
				)
			}
			dest := t.TempDir()
			extracted := int64(0)

			err := extractRegularFilesWithResourceBudget(bytes.NewReader(archive), dest, &extracted, counter, nil)

			var budgetErr *BudgetExceededError
			require.ErrorAs(t, err, &budgetErr)
			if tt.name != "file count" {
				_, statErr := os.Stat(filepath.Join(dest, "main.tf"))
				require.ErrorIs(t, statErr, os.ErrNotExist)
			}
		})
	}
}

func TestExtractArchiveCommandStreamsOutput(t *testing.T) {
	archive := tarBytes(t, tarEntry{name: "main.tf", typeflag: tar.TypeReg, body: "content"})
	archivePath := filepath.Join(t.TempDir(), "archive.tar")
	require.NoError(t, os.WriteFile(archivePath, archive, 0o600))
	dest := t.TempDir()
	extracted := int64(0)

	require.NoError(t, extractArchiveCommandWithResourceBudget(
		t.Context(), archiveHelperCommand(t, archivePath), dest, &extracted,
		int64(len(archive)), nil, nil, nil,
	))
	data, err := os.ReadFile(filepath.Join(dest, "main.tf"))
	require.NoError(t, err)
	require.Equal(t, "content", string(data))
}

func TestExtractArchiveCommandBoundsStreamBeforeExtraction(t *testing.T) {
	archive := tarBytes(t, tarEntry{name: "main.tf", typeflag: tar.TypeReg, body: "content"})
	archivePath := filepath.Join(t.TempDir(), "archive.tar")
	require.NoError(t, os.WriteFile(archivePath, archive, 0o600))
	extracted := int64(0)

	err := extractArchiveCommandWithResourceBudget(
		t.Context(), archiveHelperCommand(t, archivePath), t.TempDir(), &extracted,
		int64(len(archive)-1), nil, nil, nil,
	)

	require.ErrorContains(t, err, "git archive exceeds")
}

func TestArchiveStreamLimitCoversTarFraming(t *testing.T) {
	counter := &PackageCounter{limits: ResourceLimits{MaxPackageBytes: 256 << 20, MaxPackageFiles: 500}}
	require.Equal(t, int64(256<<20), counter.archiveContentLimit(), "extracted bytes stay bounded by the package limit")
	require.Equal(t, int64(256<<20)+501*archiveEntryFraming, counter.archiveStreamLimit())

	// The framing allowance holds for the worst case per entry: a one-byte
	// file padded to a block, under a name long enough for an extended header.
	var entries []tarEntry
	content := 0
	for i := range 500 {
		entries = append(entries, tarEntry{
			name:     fmt.Sprintf("%s/%04d.tf", strings.Repeat("deeply-nested-module-directory/", 8), i),
			typeflag: tar.TypeReg,
			body:     "x",
		})
		content++
	}
	stream := tarBytes(t, entries...)
	require.LessOrEqual(t, int64(len(stream)), int64(content)+501*archiveEntryFraming)
	require.Greater(t, len(stream), 500*1024, "the stream is far larger than its content, as tar framing makes it")
}

func archiveHelperCommand(t *testing.T, archivePath string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestArchiveCommandHelper", "--", archivePath)
	cmd.Env = append(os.Environ(), "GO_WANT_ARCHIVE_COMMAND_HELPER=1")
	return cmd
}

func TestArchiveCommandHelper(t *testing.T) {
	if os.Getenv("GO_WANT_ARCHIVE_COMMAND_HELPER") != "1" {
		return
	}
	if failure := os.Getenv("GO_WANT_ARCHIVE_COMMAND_ERROR"); failure != "" {
		_, _ = fmt.Fprint(os.Stderr, failure)
		os.Exit(1)
	}
	archivePath := os.Args[len(os.Args)-1]
	archive, err := os.Open(archivePath)
	if err != nil {
		os.Exit(1)
	}
	if _, err := io.Copy(os.Stdout, archive); err != nil {
		os.Exit(1)
	}
	if err := archive.Close(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestArchiveExtractFollowsConfigPlaceholders(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "-q", "-b", "main")
	for name, content := range map[string]string{
		"modules/local/main.tf":             "./real.hcl",
		"modules/local/real.hcl":            `module "common" { source = "../common" }`,
		"modules/json/main.tf.json":         "./body.json",
		"modules/json/body.json":            `{"module":{"common":{"source":"../common"}}}`,
		"modules/external/main.tf":          "../shared/main.tf",
		"modules/directory/main.tf":         `module "alias" { source = "../alias/nested" }`,
		"modules/alias":                     "./actual",
		"modules/actual/nested/main.tf":     `module "common" { source = "../../common" }`,
		"modules/shared/main.tf":            "../templates/nested/body.hcl",
		"modules/templates/nested/body.hcl": `module "common" { source = "../common" }`,
		"modules/common/main.tf":            `resource "null_resource" "example" {}`,
		"modules/cycle/main.tf":             "./main.tf",
		"modules/missing/main.tf":           "../absent/main.tf",
		"modules/escape/main.tf":            "../../../outside/main.tf",
		"modules/unrelated/main.tf":         "# unrelated",
	} {
		file := filepath.Join(repo, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o755))
		require.NoError(t, os.WriteFile(file, []byte(content), 0o644))
	}
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-q", "-m", "placeholder modules")
	sha := runGit(t, repo, "rev-parse", "HEAD")
	gitDir := filepath.Join(repo, ".git")
	for _, tc := range []struct {
		name, selected string
		common, fatal  bool
	}{
		{"local", "local", true, false}, {"json", "json", true, false},
		{"ordinary-metadata-unavailable", "common", false, false},
		{"external", "external", true, false}, {"directory", "directory", true, false},
		{"cycle", "cycle", false, false}, {"missing", "missing", false, false}, {"escape", "escape", false, false},
		{"budget", "external", false, true}, {"acquisition", "external", false, true},
		{"git-failure", "external", false, true}, {"tree-failure", "external", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			if tc.name == "budget" {
				ctx = WithResourceBudget(ctx, NewResourceBudget(ResourceLimits{MaxPackageBytes: 60}))
			}
			extractBase := t.TempDir()
			lookupGitDir := gitDir
			if tc.name == "tree-failure" || tc.name == "ordinary-metadata-unavailable" {
				lookupGitDir = filepath.Join(t.TempDir(), "unavailable.git")
			}
			var paths []string
			acquisitionErr := errors.New("target archive unavailable")
			runArchive := func(ctx context.Context, args []string) ([]archivePrep, error) {
				paths = append(paths, filepath.ToSlash(args[len(args)-1]))
				if tc.name == "acquisition" && len(paths) > 1 {
					return nil, acquisitionErr
				}
				if tc.name == "git-failure" && len(paths) > 1 {
					cmd := archiveHelperCommand(t, "")
					cmd.Env = append(cmd.Env, "GO_WANT_ARCHIVE_COMMAND_ERROR=fatal: pathspec 'modules/shared' did not match any files\n")
					return []archivePrep{{cmd: cmd}}, nil
				}
				if tc.name == "missing" && len(paths) > 1 {
					cmd := archiveHelperCommand(t, "")
					cmd.Env = append(cmd.Env, "GO_WANT_ARCHIVE_COMMAND_ERROR=warning: archive warning\nfatal: pathspec 'modules/absent' did not match any files\n")
					return []archivePrep{{cmd: cmd}}, nil
				}
				return localCloneArchiveCommand(gitDir)(ctx, args)
			}
			_, err := archiveExtract(ctx, lookupGitDir, extractBase, sha, "modules/"+tc.selected, runArchive, nil)
			root := archiveCacheDir(extractBase, sha)
			if tc.fatal {
				requireArchiveAcquisitionError(t, tc.name, err, acquisitionErr)
				require.NoFileExists(t, filepath.Join(root, "modules", tc.selected, "main.tf"), "failed closure must roll back its writes")
				return
			}
			require.NoError(t, err)
			if tc.common {
				require.FileExists(t, filepath.Join(root, "modules", "common", "main.tf"))
			}
			if tc.name == "external" {
				require.FileExists(t, filepath.Join(root, "modules", "shared", "main.tf"))
				require.FileExists(t, filepath.Join(root, "modules", "templates", "nested", "body.hcl"))
				require.Equal(t, []string{"modules/external", "modules/shared", "modules/templates", "modules/common"}, paths)
			}
			if tc.name == "cycle" || tc.name == "escape" || tc.name == "missing" {
				require.Equal(t, []string{"modules/" + tc.selected}, paths, "unsafe targets must not trigger archive operations")
			}
			require.NoDirExists(t, filepath.Join(root, "modules", "unrelated"))
			calls := len(paths)
			_, err = archiveExtract(ctx, gitDir, extractBase, sha, "modules/"+tc.selected, runArchive, nil)
			require.NoError(t, err)
			require.Len(t, paths, calls, "complete closures must keep the archive cache fast path")
		})
	}
}

func requireArchiveAcquisitionError(t *testing.T, name string, err, acquisitionErr error) {
	t.Helper()
	switch name {
	case "budget":
		var budgetErr *BudgetExceededError
		require.ErrorAs(t, err, &budgetErr)
	case "acquisition":
		require.ErrorIs(t, err, acquisitionErr)
	case "git-failure", "tree-failure":
		var exitErr *exec.ExitError
		require.ErrorAs(t, err, &exitErr)
	}
}
