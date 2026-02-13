package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/internal/console"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/scan"
	git "github.com/go-git/go-git/v5"
	cli "github.com/urfave/cli/v3"
)

var scanAction = &cli.Command{
	Name:  "scan",
	Usage: "Analyzes the content of a repository",
	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:     "path",
			Aliases:  []string{"p"},
			Usage:    "names of files or directories to scan",
			Required: true,
		},
		&cli.StringFlag{
			Name:    "output-path",
			Aliases: []string{"o"},
			Usage:   "directory to write the results to",
		},
		&cli.StringFlag{
			Name:  "output-name",
			Usage: "name for the results file",
			Value: "datadog-iac-scanner-result.sarif",
		},
		&cli.StringFlag{
			Name:    "payload-path",
			Aliases: []string{"d"},
			Usage:   "file name to store the internal payload JSON representation",
		},
		&cli.StringFlag{
			Name:  "metadata-path",
			Usage: "file name to store the scan metadata JSON",
		},
		&cli.IntFlag{
			Name:  "max-file-size",
			Usage: "maximum file size that will be scanned, in MB",
			Value: 5,
		},
		&cli.IntFlag{
			Name:  "max-resolver-depth",
			Usage: "maximum depth that the scanner will resolve files in",
			Value: 15,
		},
		&cli.IntFlag{
			Name:  "timeout",
			Usage: "query timeout, in seconds",
			Value: 60,
		},
		&cli.StringSliceFlag{
			Name:  "exclude-queries",
			Usage: "ids of queries to exclude",
			Value: []string{},
		},
		&cli.StringSliceFlag{
			Name:    "type",
			Aliases: []string{"t"},
			Usage:   "a list of platform types to scan",
			Value:   GetSupportedPlatforms(),
		},
	},
	Action: runScan,
}

const (
	filePerms = 0644
	dirPerms  = 0755
)

func runScan(ctx context.Context, c *cli.Command) error {
	if c.Args().Len() > 0 {
		return fmt.Errorf("unexpected arguments: %v", c.Args().Slice())
	}

	inputPaths := c.StringSlice("path")
	outputPath := c.String("output-path")
	payloadPath := c.String("payload-path")
	if outputPath != "" {
		if err := os.MkdirAll(outputPath, dirPerms); err != nil {
			return err
		}
	}
	if payloadPath != "" {
		if err := os.MkdirAll(filepath.Dir(payloadPath), dirPerms); err != nil {
			return err
		}
	}

	repoInfo, repoDir, err := getRepositoryCommitInfo(inputPaths)
	if err != nil {
		return fmt.Errorf("error retrieving repository commit information: %w", err)
	}

	config, err := scan.ReadConfiguration(ctx, repoDir)
	if err != nil {
		return fmt.Errorf("error reading the configuration: %w", err)
	}
	params := &scan.Parameters{
		CloudProvider:     []string{""},
		OutputPath:        outputPath,
		OutputName:        c.String("output-name"),
		PreviewLines:      3,
		Path:              inputPaths,
		QueriesPath:       []string{"./assets/queries"},
		LibrariesPath:     "./assets/libraries",
		ReportFormats:     []string{"sarif"},
		Platform:          selectPlatforms(c.StringSlice("type")),
		QueryExecTimeout:  c.Int("timeout"),
		DisableSecrets:    true,
		ScanID:            "console",
		MaxFileSizeFlag:   c.Int("max-file-size"),
		MaxResolverDepth:  c.Int("max-resolver-depth"),
		ExcludePlatform:   []string{""},
		PayloadPath:       payloadPath,
		SCIInfo:           model.SCIInfo{RunType: "ci", RepositoryCommitInfo: *repoInfo},
		FlagEvaluator:     featureflags.NewLocalEvaluator(),
		ExcludeCategories: config.ExcludeCategories,
		ExcludeQueries:    append(c.StringSlice("exclude-queries"), config.ExcludeQueries...),
		ExcludeResults:    config.ExcludeResults,
		ExcludeSeverities: config.ExcludeSeverities,
		ExcludePaths:      config.ExcludePaths,
		IncludeQueries:    config.IncludeQueries,
	}

	metadata, err := console.ExecuteScan(ctx, params)
	if err != nil {
		return fmt.Errorf("error during IaC scan: %w", err)
	}

	reportResult(repoDir, params.OutputPath, params.OutputName, &metadata)

	metadataPath := c.String("metadata-path")
	if err = saveMetadata(metadataPath, &metadata); err != nil {
		return fmt.Errorf("error saving the metadata JSON: %w", err)
	}

	return getExitCode(&metadata)
}

func getCommonDir(paths []string) (string, error) {
	if len(paths) < 1 {
		return "", errors.New("no paths were specified")
	}
	common, err := filepath.Abs(paths[0])
	if err != nil {
		return "", err
	}
	for _, path := range paths[1:] {
		path, err := filepath.Abs(path)
		if err != nil {
			return "", err
		}
		for path != common && !strings.HasPrefix(path, common+string(filepath.Separator)) {
			c := filepath.Dir(common)
			if c == common || common == string(filepath.Separator) {
				return "", errors.New("no common base path was found")
			}
			common = c
		}
	}
	return common, nil
}

// getRepositoryCommitInfo returns information about the Git repository at the given directory
func getRepositoryCommitInfo(repoPaths []string) (*model.RepositoryCommitInfo, string, error) {
	commonDir, err := getCommonDir(repoPaths)
	if err != nil {
		return nil, "", fmt.Errorf("could not determine repository path: %w", err)
	}
	repo, repoDir, err := openRepo(commonDir)
	if err != nil {
		return nil, "", fmt.Errorf("error opening the repository: %w", err)
	}

	remote, err := repo.Remote("origin")
	if err != nil {
		return nil, "", fmt.Errorf("error retrieving remote `origin`: %w", err)
	}
	if len(remote.Config().URLs) == 0 {
		return nil, "", errors.New("the repository doesn't have a configured remote")
	}
	out := &model.RepositoryCommitInfo{}
	out.RepositoryUrl = remote.Config().URLs[0]

	head, err := repo.Head()
	if err != nil {
		return nil, "", fmt.Errorf("error retrieving HEAD ref: %w", err)
	}
	if head == nil {
		return nil, "", errors.New("the repository doesn't have a HEAD ref")
	}
	sha := head.Hash().String()
	out.CommitSHA = sha

	if head.Name().IsBranch() {
		// We know the local branch that this commit is head of, so use that
		out.Branch = head.Name().Short()
	} else {
		// Check the references to see if there is a remote branch pointing to the head commit
		refs, err := repo.References()
		if err != nil {
			return nil, "", fmt.Errorf("error retrieving reference list: %w", err)
		}
		defer refs.Close()
		for {
			ref, err := refs.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, "", fmt.Errorf("error retrieving next reference: %w", err)
			}
			if ref.Hash() == head.Hash() && ref.Name().IsRemote() {
				out.Branch = ref.Name().Short()
				break
			}
		}
	}
	if out.Branch == "" {
		return nil, "", errors.New("could not determine the branch name for HEAD")
	}

	return out, repoDir, nil
}

// openRepo opens a Git repo, recursing up the directory tree if needed
func openRepo(repoDir string) (*git.Repository, string, error) {
	fullDir, err := filepath.Abs(repoDir)
	if err != nil {
		return nil, "", err
	}
	repoDir = fullDir
	for {
		stat, err := os.Stat(repoDir)
		if err != nil {
			return nil, "", err
		}
		if stat.IsDir() {
			repo, err := git.PlainOpen(repoDir)
			if err == nil {
				return repo, repoDir, nil
			}
			if !errors.Is(err, git.ErrRepositoryNotExists) {
				return nil, "", err
			}
		}
		newDir := filepath.Dir(repoDir)
		if newDir == repoDir || newDir == "" || newDir == "." {
			return nil, "", fmt.Errorf("no git repository found in %s", fullDir)
		}
		repoDir = newDir
	}
}

// reportResult outputs some basic data about the scan
func reportResult(repoDir, outPath, outFile string, metadata *scan.ScanMetadata) {
	if metadata.Stats.Files == 0 {
		fmt.Printf("No files were scanned in %s\n", repoDir)
	} else {
		fmt.Printf("Scanned repository %s\n", repoDir)
		fmt.Printf("%s in %v\n", plural("%d file scanned", "%d files scanned", metadata.Stats.Files), metadata.Stats.Duration)
		fmt.Printf("%s found %s\n",
			plural("%d rule", "%d rules", metadata.Stats.Rules),
			plural("%d violation", "%d violations", metadata.Stats.Violations))
	}
	if outPath != "" {
		fmt.Printf("Output written to %s\n", filepath.Join(outPath, outFile))
	}
}

func plural(singularFmt, pluralFmt string, count int) string {
	if count == 1 {
		return fmt.Sprintf(singularFmt, count)
	}
	return fmt.Sprintf(pluralFmt, count)
}

func saveMetadata(metadataPath string, metadata *scan.ScanMetadata) error {
	if metadataPath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(metadataPath), dirPerms); err != nil {
		return err
	}
	if bytes, err := json.Marshal(metadata); err != nil {
		return err
	} else if err := os.WriteFile(metadataPath, bytes, filePerms); err != nil {
		return err
	}
	return nil
}

//nolint:mnd
func getExitCode(metadata *scan.ScanMetadata) error {
	if _, ok := metadata.Stats.ViolationBreakdowns["CRITICAL"]; ok {
		return exitCode(60)
	} else if _, ok = metadata.Stats.ViolationBreakdowns["HIGH"]; ok {
		return exitCode(50)
	} else if _, ok = metadata.Stats.ViolationBreakdowns["MEDIUM"]; ok {
		return exitCode(40)
	} else if _, ok = metadata.Stats.ViolationBreakdowns["LOW"]; ok {
		return exitCode(30)
	} else if _, ok = metadata.Stats.ViolationBreakdowns["INFO"]; ok {
		return exitCode(20)
	}

	return nil
}

func selectPlatforms(platforms []string) []string {
	set := map[string]struct{}{}
	for _, p := range platforms {
		set[strings.ToLower(p)] = struct{}{}
	}
	var out []string
	for _, p := range GetSupportedPlatforms() {
		if _, found := set[strings.ToLower(p)]; found {
			out = append(out, p)
		}
	}
	return out
}
