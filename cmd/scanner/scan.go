package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/DataDog/datadog-iac-scanner/internal/console"
	"github.com/DataDog/datadog-iac-scanner/internal/console/helpers"
	"github.com/DataDog/datadog-iac-scanner/internal/constants"
	"github.com/DataDog/datadog-iac-scanner/pkg/config"
	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	iacplatforms "github.com/DataDog/datadog-iac-scanner/pkg/platforms"
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
			Name:   "timeout",
			Usage:  "(DEPRECATED) no longer has any effect; queries run to completion and slow rules are logged instead. This flag will be removed.",
			Value:  60,
			Hidden: true,
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
			Value:   iacplatforms.Supported,
		},
		&cli.BoolFlag{
			Name:   "x-parallelparsing",
			Hidden: true,
			Usage:  "(experimental, will be removed soon) parse files in parallel",
			Value:  true,
		},
		&cli.BoolFlag{
			Name:   "x-local-module-eval",
			Hidden: true,
			Usage: "(experimental) resolve Terraform local module variables before scanning; " +
				"independent of --terraform-modules-mode",
			Value: false,
		},
		&cli.StringFlag{
			Name:  "terraform-modules-mode",
			Usage: "Terraform module resolution mode: off, offline, or fetch",
			Value: string(scan.TerraformModulesModeOff),
		},
		&cli.StringFlag{
			Name:  "terraform-modules-manifest",
			Usage: "path to a Terraform modules manifest",
		},
		&cli.StringSliceFlag{
			Name:  "module-allowed-hosts",
			Usage: "host allowed for Terraform module downloads in fetch mode",
			Value: []string{},
		},
		&cli.IntFlag{
			Name:  "terraform-modules-max-depth",
			Usage: "maximum traversal depth for the Terraform module graph",
			Value: scan.DefaultRemoteModuleMaxDepth,
		},
		&cli.DurationFlag{
			Name:  "terraform-modules-fetch-timeout",
			Usage: "per-module fetch timeout",
			Value: 30 * time.Second,
		},
		&cli.DurationFlag{
			Name:  "module-resolution-timeout",
			Usage: "whole-phase Terraform module resolution timeout",
			Value: scan.DefaultModuleResolutionTimeout,
		},
		&cli.Int64Flag{
			Name:  "terraform-modules-max-bytes",
			Usage: "total size limit across all resolved Terraform modules in bytes",
			Value: scan.DefaultRemoteModuleMaxTotalBytes,
		},
		&cli.Int64Flag{
			Name:  "terraform-modules-max-package-bytes",
			Usage: "maximum extracted size of one Terraform module package in bytes",
			Value: scan.DefaultRemoteModuleMaxPackageBytes,
		},
		&cli.Int64Flag{
			Name:  "terraform-modules-max-file-bytes",
			Usage: "maximum size of one file in a Terraform module package in bytes",
			Value: scan.DefaultRemoteModuleMaxFileBytes,
		},
		&cli.IntFlag{
			Name:  "terraform-modules-max-package-files",
			Usage: "maximum number of files in one Terraform module package",
			Value: scan.DefaultRemoteModuleMaxPackageFiles,
		},
		&cli.Int64Flag{
			Name:  "terraform-modules-max-parse-bytes",
			Usage: "target bytes admitted for repository and Terraform module parsing",
		},
		&cli.StringFlag{
			Name:  "module-cache-dir",
			Usage: "directory for fetched Terraform module caches",
		},
		&cli.Int64Flag{
			Name:  "module-cache-max-bytes",
			Usage: "maximum on-disk size of the fetched Terraform module cache",
			Value: scan.DefaultRemoteModuleMaxCacheBytes,
		},
		&cli.BoolFlag{
			Name:   "x-terraform-plan",
			Hidden: true,
			Usage:  "(experimental, will be removed soon) scan terraform plans",
			Value:  false,
		},
		&cli.BoolFlag{
			Name:   "x-disable-rule-isolation",
			Hidden: true,
			Usage: "(experimental, will be removed soon) co-compile all rules and libraries into a " +
				"shared compiler instead of isolating each rule; greatly reduces memory at the cost " +
				"of per-rule compile-failure isolation",
			Value: false,
		},
		&cli.StringSliceFlag{
			Name:    "queries-path",
			Aliases: []string{"q"},
			Usage:   "a list of query directories paths",
		},
		&cli.StringFlag{
			Name:  "libraries-path",
			Usage: "path to local Rego support libraries (default: fetch from backend when using local queries-path)",
		},
		&cli.StringFlag{
			Name: "offline-bundle-path",
			Usage: "directory containing rules, libraries and configuration previously written by " +
				"`fetch-bundle`; when set, the scan makes no network calls",
		},
		&cli.StringSliceFlag{
			Name:  "report-format",
			Usage: "output report formats (valid: sarif, simple-json)",
			Value: []string{"sarif"},
		},
	},
	Action: runScan,
}

const (
	filePerms = 0644
	dirPerms  = 0755

	// staleBundleWarningAge is how old an offline bundle can be before
	// runScan warns that it may no longer reflect the latest rules.
	staleBundleWarningAge = 7 * 24 * time.Hour
)

// warnIfBundleStale logs a warning if the offline bundle at bundleDir has no
// manifest, or was fetched more than staleBundleWarningAge ago, so that
// running with stale rules is never silent.
func warnIfBundleStale(ctx context.Context, bundleDir string) {
	contextLogger := logger.FromContext(ctx)
	manifest, err := readBundleManifest(bundleDir)
	if err != nil {
		contextLogger.Warn().Err(err).Msg(
			"could not read the offline bundle manifest; the bundle's age cannot be verified")
		return
	}
	age := time.Since(manifest.FetchedAt)
	if age > staleBundleWarningAge {
		contextLogger.Warn().Msgf(
			"the offline bundle was fetched %s ago (on %s); run `fetch-bundle` again to pick up rule updates",
			age.Round(time.Hour), manifest.FetchedAt.Format(time.RFC3339))
	}
}

func validateReportFormats(formats []string) error {
	valid := map[string]struct{}{}
	validReportFormats := helpers.GetSupportedReportFormats()
	for _, f := range validReportFormats {
		valid[f] = struct{}{}
	}
	for _, f := range formats {
		if _, ok := valid[strings.ToLower(f)]; !ok {
			return fmt.Errorf("unknown report format %q; valid formats: %s",
				f, strings.Join(validReportFormats, ", "))
		}
	}
	return nil
}

func validateQueriesPaths(paths []string) ([]string, error) {
	absolutePaths, err := getAbsolutePaths(paths)
	if err != nil {
		return nil, err
	}

	for _, path := range absolutePaths {
		info, err := os.Stat(path) // follows symlink
		if err != nil {
			return nil, fmt.Errorf("invalid queries path %q", path)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("queries path %q is not a directory", path)
		}
	}
	return absolutePaths, nil
}

// nolint:gocyclo
func runScan(ctx context.Context, c *cli.Command) error {
	if c.IsSet("timeout") {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Warn().Msg(
			"the --timeout flag is deprecated and no longer has any effect; queries run to completion and slow rules are logged instead")
	}
	if c.Args().Len() > 0 {
		return fmt.Errorf("unexpected arguments: %v", c.Args().Slice())
	}

	inputPaths, err := getAbsolutePaths(c.StringSlice("path"))
	if err != nil {
		return err
	}
	outputPath, err := getAbsolutePath(c.String("output-path"))
	if err != nil {
		return err
	}
	payloadPath, err := getAbsolutePath(c.String("payload-path"))
	if err != nil {
		return err
	}
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

	offlineBundlePath := c.String("offline-bundle-path")

	var cfg *config.IacConfig
	if offlineBundlePath != "" {
		cfgBytes, err := os.ReadFile(filepath.Clean(filepath.Join(offlineBundlePath, bundleConfigFileName)))
		if err != nil {
			return errorWithExitCode(fmt.Errorf("error reading the offline configuration bundle: %w", err), constants.InvalidConfigErrorCode)
		}
		cfg, err = config.ParseConfig(cfgBytes)
		if err != nil {
			return errorWithExitCode(fmt.Errorf("error parsing the offline configuration bundle: %w", err), constants.InvalidConfigErrorCode)
		}
		if cfg == nil {
			cfg = &config.IacConfig{}
		}
		warnIfBundleStale(ctx, offlineBundlePath)
	} else {
		cfg, _, err = config.ReadConfiguration(ctx, repoDir, config.WithDatadog(datadog.NewDatadogClient(), repoInfo.RepositoryUrl))
		if err != nil {
			outErr := fmt.Errorf("error reading the configuration: %w", err)
			if te := (*config.InvalidLocalConfigError)(nil); errors.As(err, &te) {
				outErr = errorWithExitCode(outErr, constants.InvalidConfigErrorCode)
			}
			return outErr
		}
	}
	excludePaths, err := getRepoRelativePaths(repoDir, cfg.IgnorePaths)
	if err != nil {
		return errorWithExitCode(fmt.Errorf("invalid path in IaC configuration: %w", err), constants.InvalidConfigErrorCode)
	}
	cfg.IgnorePaths = excludePaths
	onlyPaths, err := getRepoRelativePaths(repoDir, cfg.OnlyPaths)
	if err != nil {
		return errorWithExitCode(fmt.Errorf("invalid path in IaC configuration: %w", err), constants.InvalidConfigErrorCode)
	}
	cfg.OnlyPaths = onlyPaths
	cfg.IgnoreRules = append(c.StringSlice("exclude-queries"), cfg.IgnoreRules...)

	for ruleID, rc := range cfg.RuleConfigs {
		resolvedIgnore, pathErr := getRepoRelativePaths(repoDir, rc.IgnorePaths)
		if pathErr != nil {
			return errorWithExitCode(fmt.Errorf("invalid ignore-path in rule-config %q: %w", ruleID, pathErr), constants.InvalidConfigErrorCode)
		}
		resolvedOnly, pathErr := getRepoRelativePaths(repoDir, rc.OnlyPaths)
		if pathErr != nil {
			return errorWithExitCode(fmt.Errorf("invalid only-path in rule-config %q: %w", ruleID, pathErr), constants.InvalidConfigErrorCode)
		}
		rc.IgnorePaths = resolvedIgnore
		rc.OnlyPaths = resolvedOnly
		cfg.RuleConfigs[ruleID] = rc
	}

	reportFormats := c.StringSlice("report-format")
	if err := validateReportFormats(reportFormats); err != nil {
		return errorWithExitCode(err, constants.InvalidConfigErrorCode)
	}
	moduleMode, err := scan.ParseTerraformModulesMode(c.String("terraform-modules-mode"))
	if err != nil {
		return errorWithExitCode(err, constants.InvalidConfigErrorCode)
	}
	if moduleMode == scan.TerraformModulesModeOff &&
		(c.String("terraform-modules-manifest") != "" ||
			len(c.StringSlice("module-allowed-hosts")) > 0 ||
			c.String("module-cache-dir") != "") {
		return errorWithExitCode(
			errors.New("terraform module resolver options require --terraform-modules-mode=offline or fetch"),
			constants.InvalidConfigErrorCode,
		)
	}
	if moduleMode == scan.TerraformModulesModeOffline &&
		(len(c.StringSlice("module-allowed-hosts")) > 0 ||
			c.String("module-cache-dir") != "") {
		return errorWithExitCode(
			errors.New("network and cache options require --terraform-modules-mode=fetch"),
			constants.InvalidConfigErrorCode,
		)
	}

	queriesPath := c.StringSlice("queries-path")
	queriesPath, err = validateQueriesPaths(queriesPath)
	if err != nil {
		return errorWithExitCode(fmt.Errorf("path parsing exited with error: %q", err), constants.InvalidConfigErrorCode)
	}

	changedDefaultQueryPath := len(queriesPath) > 0
	if !changedDefaultQueryPath {
		queriesPath = []string{"./assets/queries"}
	}

	librariesPath := "./assets/libraries"
	changedDefaultLibrariesPath := false
	if lp := c.String("libraries-path"); lp != "" {
		validated, err := validateQueriesPaths([]string{lp})
		if err != nil {
			return errorWithExitCode(fmt.Errorf("libraries path parsing exited with error: %q", err), constants.InvalidConfigErrorCode)
		}
		librariesPath = validated[0]
		changedDefaultLibrariesPath = true
	}

	params := &scan.Parameters{
		CloudProvider:               []string{""},
		OutputPath:                  outputPath,
		OutputName:                  c.String("output-name"),
		PreviewLines:                3,
		RepoPath:                    repoDir,
		Path:                        inputPaths,
		QueriesPath:                 queriesPath,
		ChangedDefaultQueryPath:     changedDefaultQueryPath,
		LibrariesPath:               librariesPath,
		ChangedDefaultLibrariesPath: changedDefaultLibrariesPath,
		ReportFormats:               reportFormats,
		Platform:                    selectPlatforms(c.StringSlice("type")),
		DisableSecrets:              true,
		ScanID:                      "console",
		MaxFileSizeFlag:             c.Int("max-file-size"),
		MaxResolverDepth:            c.Int("max-resolver-depth"),
		PayloadPath:                 payloadPath,
		SCIInfo:                     model.SCIInfo{RepositoryDir: repoDir, RepositoryCommitInfo: *repoInfo},
		FlagEvaluator:               getFeatureFlagEvaluator(c),
		Config:                      *cfg,
		ShouldScanTfPlans:           c.Bool("x-terraform-plan"),
		DisableRuleIsolation:        c.Bool("x-disable-rule-isolation"),
		TerraformModulesMode:        moduleMode,
		RemoteModulesManifestPath:   c.String("terraform-modules-manifest"),
		RemoteModulesHostAllowlist:  c.StringSlice("module-allowed-hosts"),
		ModuleMaxDepth:              c.Int("terraform-modules-max-depth"),
		ModuleFetchTimeout:          c.Duration("terraform-modules-fetch-timeout"),
		ModuleResolutionTimeout:     c.Duration("module-resolution-timeout"),
		MaxModuleBytesTotal:         c.Int64("terraform-modules-max-bytes"),
		MaxModulePackageBytes:       c.Int64("terraform-modules-max-package-bytes"),
		MaxModuleFileBytes:          c.Int64("terraform-modules-max-file-bytes"),
		MaxModulePackageFiles:       c.Int("terraform-modules-max-package-files"),
		MaxModuleParseBytes:         c.Int64("terraform-modules-max-parse-bytes"),
		RemoteModulesCacheDir:       c.String("module-cache-dir"),
		MaxModuleCacheBytes:         c.Int64("module-cache-max-bytes"),
	}

	var opts []scan.ClientOption
	if offlineBundlePath != "" {
		offlineClient, err := datadog.NewLocalFileClient(
			filepath.Join(offlineBundlePath, bundleRulesFileName),
			filepath.Join(offlineBundlePath, bundleLibrariesFileName),
		)
		if err != nil {
			return errorWithExitCode(fmt.Errorf("error loading the offline bundle: %w", err), constants.InvalidConfigErrorCode)
		}
		opts = append(opts, scan.WithQuerySourceFactory(func(_ context.Context, paramsPlatforms []string) (source.QueriesSource, error) {
			return source.NewDatadogSource(
				offlineClient,
				source.WithWantedPlatforms(paramsPlatforms),
				source.WithWantedCloudProviders(params.CloudProvider),
			)
		}))
	}

	metadata, err := console.ExecuteScan(ctx, params, opts...)
	if err != nil {
		return errorWithExitCode(fmt.Errorf("error during IaC scan: %w", err), constants.EngineErrorCode)
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
		if isUnsupportedRefStorage(err) {
			return getRepositoryCommitInfoWithGit(commonDir)
		}
		return nil, "", fmt.Errorf("error opening the repository: %w", err)
	}

	remote, err := repo.Remote("origin")
	if err != nil {
		return getRepositoryCommitInfoWithGit(commonDir)
	}
	if len(remote.Config().URLs) == 0 {
		return getRepositoryCommitInfoWithGit(commonDir)
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

	return out, repoDir, nil
}

func isUnsupportedRefStorage(err error) bool {
	return errors.Is(err, git.ErrUnsupportedExtensionRepositoryFormatVersion) &&
		strings.Contains(strings.ToLower(err.Error()), "refstorage")
}

func getRepositoryCommitInfoWithGit(path string) (*model.RepositoryCommitInfo, string, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return nil, "", err
	}
	if !stat.IsDir() {
		path = filepath.Dir(path)
	}

	repoDir, err := runGit(path, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, "", fmt.Errorf("error determining repository root: %w", err)
	}
	repoDir = filepath.Clean(filepath.FromSlash(repoDir))
	remoteURL, err := runGit(repoDir, "remote", "get-url", "origin")
	if err != nil {
		return nil, "", fmt.Errorf("error retrieving remote `origin`: %w", err)
	}
	sha, err := runGit(repoDir, "rev-parse", "HEAD")
	if err != nil {
		return nil, "", fmt.Errorf("error retrieving HEAD ref: %w", err)
	}

	branch, err := runGit(repoDir, "symbolic-ref", "--quiet", "--short", "HEAD")
	if err != nil {
		refs, err := runGit(repoDir, "for-each-ref", "--format=%(refname:short)%00%(symref)", "--points-at", "HEAD", "refs/remotes")
		if err != nil {
			return nil, "", fmt.Errorf("error retrieving reference list: %w", err)
		}
		branch = firstRemoteBranch(refs)
	}

	return &model.RepositoryCommitInfo{
		RepositoryUrl: remoteURL,
		CommitSHA:     sha,
		Branch:        branch,
	}, repoDir, nil
}

func firstRemoteBranch(refs string) string {
	for _, line := range strings.Split(refs, "\n") {
		line = strings.TrimSuffix(line, "\r")
		name, symref, found := strings.Cut(line, "\x00")
		if found && name != "" && symref == "" {
			return name
		}
	}
	return ""
}

func runGit(repoDir string, args ...string) (string, error) {
	cmdArgs := append([]string{"-C", repoDir}, args...)
	//nolint:gosec // Arguments are fixed by internal callers.
	cmd := exec.Command("git", cmdArgs...)
	cmd.Env = gitEnvironment()
	output, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			return "", err
		}
		return "", fmt.Errorf("%s: %w", message, err)
	}
	return trimGitOutputTerminator(string(output)), nil
}

func trimGitOutputTerminator(output string) string {
	return strings.TrimSuffix(strings.TrimSuffix(output, "\n"), "\r")
}

func gitEnvironment() []string {
	env := os.Environ()
	cleanEnv := env[:0]
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(name) {
		case "GIT_DIR",
			"GIT_WORK_TREE",
			"GIT_COMMON_DIR",
			"GIT_INDEX_FILE",
			"GIT_OBJECT_DIRECTORY",
			"GIT_ALTERNATE_OBJECT_DIRECTORIES",
			"GIT_NAMESPACE":
			continue
		default:
			cleanEnv = append(cleanEnv, entry)
		}
	}
	return cleanEnv
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
	for _, p := range iacplatforms.Supported {
		if _, found := set[strings.ToLower(p)]; found {
			out = append(out, p)
		}
	}
	return out
}

func localModuleEvalEnabled(legacyLocalModuleEval bool, modulesMode scan.TerraformModulesMode) bool {
	return legacyLocalModuleEval || modulesMode != scan.TerraformModulesModeOff
}

func getFeatureFlagEvaluator(c *cli.Command) featureflags.FlagEvaluator {
	moduleMode, _ := scan.ParseTerraformModulesMode(c.String("terraform-modules-mode"))
	overrides := map[string]bool{
		featureflags.IaCEnableKicsParallelFileParsing: c.Bool("x-parallelparsing"),
		featureflags.IacEnableLocalModuleEval: localModuleEvalEnabled(
			c.Bool("x-local-module-eval"),
			moduleMode,
		),
	}
	return featureflags.NewLocalEvaluatorWithOverrides(overrides)
}

func getAbsolutePath(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	return filepath.Abs(path)
}

func getAbsolutePaths(paths []string) ([]string, error) {
	var out []string
	for _, p := range paths {
		res, err := getAbsolutePath(p)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func getRepoRelativePaths(repoDir string, paths []string) ([]string, error) {
	var out []string
	for _, p := range paths {
		if p == "" {
			continue
		}
		if filepath.IsAbs(p) {
			rel, err := filepath.Rel(repoDir, p)
			if err != nil {
				return nil, err
			}
			p = rel
		}
		if !filepath.IsLocal(p) {
			return nil, fmt.Errorf("path %q is not relative to the repository root", p)
		}
		out = append(out, filepath.Join(repoDir, filepath.Clean(p)))
	}
	return out, nil
}
