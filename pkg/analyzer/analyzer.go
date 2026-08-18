/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package analyzer

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"

	"github.com/DataDog/datadog-iac-scanner/internal/metrics"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/provider"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/pkg/errors"
)

// move the openApi regex to public to be used on file.go
// openAPIRegex - Regex that finds OpenAPI defining property "openapi" or "swagger"
// openAPIRegexInfo - Regex that finds OpenAPI defining property "info"
// openAPIRegexPath - Regex that finds OpenAPI defining property "paths", "components", or "webhooks" (from 3.1.0)
// cloudRegex - Regex that finds CloudFormation defining property "Resources"
// k8sRegex - Regex that finds Kubernetes defining property "apiVersion"
// k8sRegexKind - Regex that finds Kubernetes defining property "kind"
// k8sRegexMetadata - Regex that finds Kubernetes defining property "metadata"
// k8sRegexSpec - Regex that finds Kubernetes defining property "spec"
var (
	OpenAPIRegex                                    = regexp.MustCompile(`("(openapi|swagger)"|(openapi|swagger))\s*:`)
	OpenAPIRegexInfo                                = regexp.MustCompile(`("info"|info)\s*:`)
	OpenAPIRegexPath                                = regexp.MustCompile(`("(paths|components|webhooks)"|(paths|components|webhooks))\s*:`)
	armRegexContentVersion                          = regexp.MustCompile(`"contentVersion"\s*:`)
	armRegexResources                               = regexp.MustCompile(`"resources"\s*:`)
	cloudRegex                                      = regexp.MustCompile(`("Resources"|Resources)\s*:`)
	k8sRegex                                        = regexp.MustCompile(`("apiVersion"|apiVersion)\s*:`)
	k8sRegexKind                                    = regexp.MustCompile(`("kind"|kind)\s*:`)
	tfPlanRegexPV                                   = regexp.MustCompile(`"planned_values"\s*:`)
	tfPlanRegexRC                                   = regexp.MustCompile(`"resource_changes"\s*:`)
	tfPlanRegexConf                                 = regexp.MustCompile(`"configuration"\s*:`)
	tfPlanRegexTV                                   = regexp.MustCompile(`"terraform_version"\s*:`)
	cdkTfRegexMetadata                              = regexp.MustCompile(`"metadata"\s*:`)
	cdkTfRegexStackName                             = regexp.MustCompile(`"stackName"\s*:`)
	cdkTfRegexTerraform                             = regexp.MustCompile(`"terraform"\s*:`)
	artifactsRegexKind                              = regexp.MustCompile(`("kind"|kind)\s*:`)
	artifactsRegexProperties                        = regexp.MustCompile(`("properties"|properties)\s*:`)
	artifactsRegexParametes                         = regexp.MustCompile(`("parameters"|parameters)\s*:`)
	policyAssignmentArtifactRegexPolicyDefinitionID = regexp.MustCompile(`("policyDefinitionId"|policyDefinitionId)\s*:`)
	roleAssignmentArtifactRegexPrincipalIds         = regexp.MustCompile(`("principalIds"|principalIds)\s*:`)
	roleAssignmentArtifactRegexRoleDefinitionID     = regexp.MustCompile(`("roleDefinitionId"|roleDefinitionId)\s*:`)
	templateArtifactRegexParametes                  = regexp.MustCompile(`("template"|template)\s*:`)
	blueprintpRegexTargetScope                      = regexp.MustCompile(`("targetScope"|targetScope)\s*:`)
	blueprintpRegexProperties                       = regexp.MustCompile(`("properties"|properties)\s*:`)
	buildahRegex                                    = regexp.MustCompile(`buildah\s*from\s*\w+`)
	crossPlaneRegex                                 = regexp.MustCompile(`"?apiVersion"?\s*:\s*(\w+\.)+crossplane\.io/v\w+\s*`)
	knativeRegex                                    = regexp.MustCompile(`"?apiVersion"?\s*:\s*(\w+\.)+knative\.dev/v\w+\s*`)
	pulumiNameRegex                                 = regexp.MustCompile(`name\s*:`)
	pulumiRuntimeRegex                              = regexp.MustCompile(`runtime\s*:`)
	pulumiResourcesRegex                            = regexp.MustCompile(`resources\s*:`)
	serverlessServiceRegex                          = regexp.MustCompile(`service\s*:`)
	serverlessProviderRegex                         = regexp.MustCompile(`(^|\n)provider\s*:`)
	cicdOnRegex                                     = regexp.MustCompile(`\s*on:\s*`)
	cicdJobsRegex                                   = regexp.MustCompile(`\s*jobs:\s*`)
	githubActionManifestRunsRegex                   = regexp.MustCompile(`(^|\n)runs:\s*`)
	githubActionManifestUsingRegex                  = regexp.MustCompile(`\s*using:\s*['"]?(composite|docker|node\d+)`)
	dependabotVersionRegex                          = regexp.MustCompile(`\s*version:\s*`)
	dependabotUpdatesRegex                          = regexp.MustCompile(`\s*updates:\s*`)
	dependabotPackageEcosystemRegex                 = regexp.MustCompile(`\s*package-ecosystem:\s*`)
)

var (
	listKeywordsGoogleDeployment = []string{"resources"}
	armRegexTypes                = []string{"blueprint", "templateArtifact", "roleAssignmentArtifact", "policyAssignmentArtifact"}
	possibleFileTypes            = map[string]bool{
		yml:            true,
		yaml:           true,
		json:           true,
		sh:             true,
		extDockerfile:  true,
		nameDockerfile: true,
		extDebian:      true,
		extUbi8:        true,
		extTf:          true,
		extTfvars:      true,
		extProto:       true,
		extCfg:         true,
		extConf:        true,
		extIni:         true,
		extBicepFile:   true,
	}
	supportedRegexes = map[string][]string{
		"azureresourcemanager": append(armRegexTypes, arm),
		"buildah":              {"buildah"},
		"cicd":                 {"cicd", "dependabot", "githubAction"},
		"cloudformation":       {"cloudformation"},
		"crossplane":           {"crossplane"},
		"knative":              {"knative"},
		"kubernetes":           {"kubernetes"},
		"openapi":              {"openapi"},
		"terraform":            {"terraform", "cdkTf"},
		"pulumi":               {"pulumi"},
		"serverlessfw":         {"serverlessfw"},
	}
	listKeywordsAnsible = []string{"name", "gather_facts",
		"hosts", "tasks", "become", "with_items", "with_dict",
		"when", "become_pass", "become_exe", "become_flags"}
	playBooks               = "playbooks"
	ansibleHost             = []string{"all", "ungrouped"}
	listKeywordsAnsibleHots = []string{"hosts", "children"}
)

// PossibleFileTypes returns the sorted set of file extensions and filenames the
// scanner can analyze. Exposed so the server's supported-files endpoint can
// stay in sync with the scanner's capabilities.
func PossibleFileTypes() []string {
	out := make([]string, 0, len(possibleFileTypes))
	for k := range possibleFileTypes {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

const (
	cdkTf                 = "cdkTf"
	yml                   = ".yml"
	yaml                  = ".yaml"
	json                  = ".json"
	sh                    = ".sh"
	arm                   = "azureresourcemanager"
	bicep                 = "bicep"
	kubernetes            = "kubernetes"
	terraform             = "terraform"
	gdm                   = "googledeploymentmanager"
	ansible               = "ansible"
	grpc                  = "grpc"
	dockerfile            = "dockerfile"
	crossplane            = "crossplane"
	knative               = "knative"
	cicd                  = "cicd"
	dependabot            = "dependabot"
	githubAction          = "githubAction"
	sizeMb                = 1048576
	extDockerfile         = ".dockerfile"
	nameDockerfile        = "Dockerfile"
	extPossibleDockerfile = "possibleDockerfile"
	extUbi8               = ".ubi8"
	extDebian             = ".debian"
	extTf                 = ".tf"
	extTfvars             = ".tfvars"
	extBicepFile          = ".bicep"
	extProto              = ".proto"
	extCfg                = ".cfg"
	extConf               = ".conf"
	extIni                = ".ini"
)

type Parameters struct {
	Results     string
	Path        []string
	MaxFileSize int
}

// regexSlice is a struct to contain a slice of regex
type regexSlice struct {
	regex []*regexp.Regexp
}

type analyzerInfo struct {
	typesFlag       []string
	filePath        string
	maxFileSize     int
	filePlatformMap *sync.Map
	contentCache    *sync.Map
	helmCache       *sync.Map
}

// Analyzer keeps all the relevant info for the function Analyze
type Analyzer struct {
	RepoPath          string
	Paths             []string
	Types             []string
	Exc               []string
	Only              []string
	GitIgnoreFileName string
	ExcludeGitIgnore  bool
	MaxFileSize       int
	NumWorkers        int
}

// types is a map that contains the regex by type
var types = map[string]regexSlice{
	"openapi": {
		regex: []*regexp.Regexp{
			OpenAPIRegex,
			OpenAPIRegexInfo,
			OpenAPIRegexPath,
		},
	},
	"kubernetes": {
		regex: []*regexp.Regexp{
			k8sRegex,
			k8sRegexKind,
		},
	},
	"crossplane": {
		regex: []*regexp.Regexp{
			crossPlaneRegex,
			k8sRegexKind,
		},
	},
	"knative": {
		regex: []*regexp.Regexp{
			knativeRegex,
			k8sRegexKind,
		},
	},
	"cloudformation": {
		regex: []*regexp.Regexp{
			cloudRegex,
		},
	},
	"azureresourcemanager": {
		[]*regexp.Regexp{
			armRegexContentVersion,
			armRegexResources,
		},
	},
	"terraform": {
		[]*regexp.Regexp{
			tfPlanRegexConf,
			tfPlanRegexPV,
			tfPlanRegexRC,
			tfPlanRegexTV,
		},
	},
	"cdkTf": {
		[]*regexp.Regexp{
			cdkTfRegexMetadata,
			cdkTfRegexStackName,
			cdkTfRegexTerraform,
		},
	},
	"policyAssignmentArtifact": {
		[]*regexp.Regexp{
			artifactsRegexKind,
			artifactsRegexProperties,
			artifactsRegexParametes,
			policyAssignmentArtifactRegexPolicyDefinitionID,
		},
	},
	"roleAssignmentArtifact": {
		[]*regexp.Regexp{
			artifactsRegexKind,
			artifactsRegexProperties,
			roleAssignmentArtifactRegexPrincipalIds,
			roleAssignmentArtifactRegexRoleDefinitionID,
		},
	},
	"templateArtifact": {
		[]*regexp.Regexp{
			artifactsRegexKind,
			artifactsRegexProperties,
			artifactsRegexParametes,
			templateArtifactRegexParametes,
		},
	},
	"blueprint": {
		[]*regexp.Regexp{
			blueprintpRegexTargetScope,
			blueprintpRegexProperties,
		},
	},
	"buildah": {
		[]*regexp.Regexp{
			buildahRegex,
		},
	},
	"pulumi": {
		[]*regexp.Regexp{
			pulumiNameRegex,
			pulumiRuntimeRegex,
			pulumiResourcesRegex,
		},
	},
	"serverlessfw": {
		[]*regexp.Regexp{
			serverlessServiceRegex,
			serverlessProviderRegex,
		},
	},
	"cicd": {
		[]*regexp.Regexp{
			cicdOnRegex,
			cicdJobsRegex,
		},
	},
	"dependabot": {
		[]*regexp.Regexp{
			dependabotVersionRegex,
			dependabotUpdatesRegex,
			dependabotPackageEcosystemRegex,
		},
	},
	"githubAction": {
		[]*regexp.Regexp{
			githubActionManifestRunsRegex,
			githubActionManifestUsingRegex,
		},
	},
}

var defaultConfigSuffixes = []string{"pnpm-lock.yaml"}

// Required substrings per platform; skip regex when none are present.
var contentHints = map[string][][]byte{
	"kubernetes":               {[]byte("apiVersion")},
	"crossplane":               {[]byte("crossplane.io")},
	"knative":                  {[]byte("knative.dev")},
	"cloudformation":           {[]byte("Resources")},
	"openapi":                  {[]byte("openapi"), []byte("swagger")},
	"azureresourcemanager":     {[]byte("contentVersion")},
	"terraform":                {[]byte("planned_values")},
	"cdkTf":                    {[]byte("stackName")},
	"policyAssignmentArtifact": {[]byte("policyDefinitionId")},
	"roleAssignmentArtifact":   {[]byte("principalIds")},
	"blueprint":                {[]byte("targetScope")},
	"buildah":                  {[]byte("buildah")},
	"dependabot":               {[]byte("package-ecosystem")},
	"githubAction":             {[]byte("using:")},
	"cicd":                     {[]byte("jobs:")},
}

// nolint:gocyclo
// Analyze will go through the slice paths given and determine what type of queries should be loaded
// should be loaded based on the extension of the file and the content
func Analyze(ctx context.Context, a *Analyzer) (model.AnalyzedPaths, error) {
	contextLogger := logger.FromContext(ctx)
	// start metrics for file analyzer
	metrics.Metric.Start("file_type_analyzer")
	defer metrics.Metric.Stop()
	returnAnalyzedPaths := model.AnalyzedPaths{
		Types:       make([]string, 0),
		Exc:         make([]string, 0),
		ExpectedLOC: 0,
	}

	gitDir := filepath.Join(a.RepoPath, ".git")

	var err error
	var files []string
	var chartRoots []string
	var totalFiles int
	// results is the channel shared by the workers that contains the types found
	results := make(chan string)
	locCount := make(chan int)
	ignoreFiles := make([]string, 0)
	projectConfigFiles := make([]string, 0)
	hasGitIgnoreFile, gitIgnore := shouldConsiderGitIgnoreFile(ctx, a.RepoPath, a.GitIgnoreFileName, a.ExcludeGitIgnore)
	if a.Exc, err = expandPaths(ctx, a.Exc); err != nil {
		return returnAnalyzedPaths, fmt.Errorf("failed to expand ignore-paths: %w", err)
	}
	if a.Only, err = expandPaths(ctx, a.Only); err != nil {
		return returnAnalyzedPaths, fmt.Errorf("failed to expand only-paths: %w", err)
	}
	// get all the files inside the given paths
	for _, path := range a.Paths {
		pathInfo, statErr := os.Stat(path)
		if statErr != nil {
			return returnAnalyzedPaths, errors.Wrap(statErr, "failed to analyze path")
		}
		singleFilePath := !pathInfo.IsDir()
		walkRootDirChecked := false
		if err := filepath.WalkDir(path, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if path == gitDir {
				a.Exc = append(a.Exc, filepath.ToSlash(path))
				return filepath.SkipDir
			}

			trimmedPath, relErr := filepath.Rel(a.RepoPath, path)
			insideRepo := relErr == nil &&
				trimmedPath != ".." &&
				!strings.HasPrefix(trimmedPath, ".."+string(os.PathSeparator))

			if d.IsDir() {
				if provider.IsTerraformCacheDir(path) {
					return filepath.SkipDir
				}
				// When the walk root starts below an ignored ancestor, git never
				// enters that ancestor so MatchesDir on the root basename is not
				// enough. One parent check per WalkDir root preserves pruning
				// without re-testing every file or directory in the tree.
				if insideRepo && hasGitIgnoreFile && !walkRootDirChecked {
					walkRootDirChecked = true
					if gitIgnore.MatchesParentDir(trimmedPath) {
						norm := filepath.ToSlash(path)
						ignoreFiles = append(ignoreFiles, norm)
						a.Exc = append(a.Exc, norm)
						return filepath.SkipDir
					}
				}
				// Pruning the subtree is cheaper than testing every file below
				// it, and it is what makes an ignored directory final: git
				// cannot re-include a file whose parent is excluded, so the
				// files under it must never be considered at all. The directory
				// itself is recorded as excluded so downstream walks skip it too.
				if insideRepo && hasGitIgnoreFile && gitIgnore.MatchesDir(trimmedPath) {
					norm := filepath.ToSlash(path)
					ignoreFiles = append(ignoreFiles, norm)
					a.Exc = append(a.Exc, norm)
					return filepath.SkipDir
				}
				return nil
			}

			totalFiles++

			if d.Type()&fs.ModeSymlink != 0 {
				if _, statErr := os.Stat(path); statErr != nil {
					norm := filepath.ToSlash(path)
					ignoreFiles = append(ignoreFiles, norm)
					a.Exc = append(a.Exc, norm)
					return nil
				}
			}

			if filepath.Base(path) == "Chart.yaml" {
				chartRoots = append(chartRoots, filepath.ToSlash(filepath.Dir(path)))
			}

			ext := utils.ExtensionFromPath(path)
			if ext == "" {
				return nil
			}
			if _, ok := possibleFileTypes[ext]; !ok {
				return nil
			}

			if isConfigFile(path, defaultConfigSuffixes) {
				norm := filepath.ToSlash(path)
				projectConfigFiles = append(projectConfigFiles, norm)
				a.Exc = append(a.Exc, norm)
				return nil
			}

			if insideRepo && hasGitIgnoreFile &&
				(gitIgnore.MatchesPath(trimmedPath) ||
					(singleFilePath && gitIgnore.MatchesParentDir(trimmedPath))) {
				norm := filepath.ToSlash(path)
				ignoreFiles = append(ignoreFiles, norm)
				a.Exc = append(a.Exc, norm)
				return nil
			}

			if isExcludedFile(path, a.Exc) || !isIncludedFile(path, a.Only) {
				return nil
			}

			files = append(files, filepath.ToSlash(path))
			return nil
		}); err != nil {
			contextLogger.Error().Msgf("failed to analyze path %s: %s", path, err)
		}
	}

	// unwanted is the channel shared by the workers that contains the unwanted files that the parser will ignore
	unwanted := make(chan string, len(files))

	typesFlag := typesLower(a.Types)

	var filePlatformMap sync.Map
	var contentCache sync.Map
	var helmCacheLocal sync.Map

	// Detect each file's type with a bounded worker pool. File-type detection
	// reads file content (I/O-bound), so it does not consume the shared CPU
	// budget and fans out wider than the core count (same [min,max] bounds as the
	// filesystem reader). Workers write into the results/unwanted/locCount
	// channels, which computeValues drains concurrently below; the channels are
	// closed once all files are processed.
	//
	// forEachErr is written by the goroutine before it closes the channels and
	// read only after computeValues has drained them to completion; the channel
	// close/receive ordering guarantees the write is visible here without a race.
	var forEachErr error
	go func() {
		forEachErr = utils.ForEach(ctx, files,
			utils.PoolOptions{Workers: a.NumWorkers, MinWorkers: utils.IOMinWorkers, MaxWorkers: utils.IOMaxWorkers},
			func(ctx context.Context, filePath string, _ int) error {
				analyzerInfo := &analyzerInfo{
					typesFlag:       typesFlag,
					filePath:        filePath,
					maxFileSize:     a.MaxFileSize,
					filePlatformMap: &filePlatformMap,
					contentCache:    &contentCache,
					helmCache:       &helmCacheLocal,
				}
				analyzerInfo.worker(ctx, results, unwanted, locCount)
				return nil
			})
		close(unwanted)
		close(results)
		close(locCount)
	}()

	availableTypes, unwantedPaths, loc := computeValues(results, unwanted, locCount)
	// A canceled scan must surface the cancellation rather than be reported as a
	// successful analysis with partial results.
	if forEachErr != nil {
		return returnAnalyzedPaths, forEachErr
	}
	multiPlatformTypeCheck(&availableTypes)
	unwantedPaths = append(unwantedPaths, ignoreFiles...)
	unwantedPaths = append(unwantedPaths, projectConfigFiles...)
	returnAnalyzedPaths.Types = availableTypes
	returnAnalyzedPaths.Exc = unwantedPaths
	returnAnalyzedPaths.ExpectedLOC = loc

	fp := make(map[string]string, len(files))
	filePlatformMap.Range(func(k, v interface{}) bool {
		fp[k.(string)] = v.(string)
		return true
	})
	returnAnalyzedPaths.FilePlatform = fp
	returnAnalyzedPaths.TotalFiles = totalFiles
	returnAnalyzedPaths.ChartRoots = chartRoots

	unwantedSet := make(map[string]struct{}, len(unwantedPaths))
	for _, p := range unwantedPaths {
		unwantedSet[p] = struct{}{}
	}
	inventory := make([]string, 0, len(files))
	for _, f := range files {
		if _, skip := unwantedSet[f]; skip {
			continue
		}
		inventory = append(inventory, f)
	}
	returnAnalyzedPaths.Inventory = inventory

	cacheOut := make(map[string][]byte)
	contentCache.Range(func(k, v interface{}) bool {
		cacheOut[k.(string)] = v.([]byte)
		return true
	})
	returnAnalyzedPaths.ContentCache = cacheOut

	return returnAnalyzedPaths, nil
}

// worker determines the type of the file by ext (dockerfile and terraform)/content and
// writes the answer to the results channel
// if no types were found, the worker will write the path of the file in the unwanted channel
func (a *analyzerInfo) worker(ctx context.Context, results, unwanted chan<- string, locCount chan<- int) {
	ext := utils.ExtensionFromPath(a.filePath)
	if ext == "" {
		return
	}

	if a.maxFileSize >= 0 && !isContentClassifiedExt(ext) {
		if info, err := os.Stat(a.filePath); err == nil {
			if float64(info.Size())/float64(sizeMb) > float64(a.maxFileSize) {
				contextLogger := logger.FromContext(ctx)
				contextLogger.Warn().Msgf(
					"file %s exceeds maximum file size of %d Mb", a.filePath, a.maxFileSize)
				unwanted <- a.filePath
				return
			}
		}
	}

	content, ok, tooLarge := a.readClassifyContent(ctx, ext)
	if tooLarge {
		unwanted <- a.filePath
		return
	}
	if !ok {
		return
	}

	platform := classifyFile(ctx, vfs.DiskFS{}, a.filePath, content, a.typesFlag, a.helmCache)
	if platform == "" {
		unwanted <- a.filePath
		return
	}
	if !a.isAvailableType(platform) {
		if isContentClassifiedExt(ext) {
			unwanted <- a.filePath
		}
		return
	}
	a.persistWorkerState(content, platform)
	results <- platform
	// Counted only once the file is known to be scanned, and from the content
	// read for classification when there is any, so the file is opened once.
	locCount <- a.countLines(ctx, content)
}

func (a *analyzerInfo) countLines(ctx context.Context, content []byte) int {
	if content != nil {
		return utils.CountLines(content)
	}
	lineCount, err := utils.LineCounter(ctx, a.filePath)
	if err != nil {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Err(err).Msgf("failed to count lines of '%s'", a.filePath)
	}
	return lineCount
}

func isContentClassifiedExt(ext string) bool {
	return ext == yaml || ext == yml || ext == json || ext == sh
}

func (a *analyzerInfo) readClassifyContent(ctx context.Context, ext string) (content []byte, ok, tooLarge bool) {
	if !isContentClassifiedExt(ext) {
		return nil, true, false
	}
	file, err := os.Open(filepath.Clean(a.filePath))
	if err != nil {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Error().Msgf("failed to analyze file: %s", err)
		return nil, false, false
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			contextLogger := logger.FromContext(ctx)
			contextLogger.Err(closeErr).Msgf("failed to close '%s'", a.filePath)
		}
	}()

	size := int64(-1)
	if info, statErr := file.Stat(); statErr == nil {
		size = info.Size()
		if a.maxFileSize >= 0 && float64(size)/float64(sizeMb) > float64(a.maxFileSize) {
			contextLogger := logger.FromContext(ctx)
			contextLogger.Warn().Msgf(
				"file %s exceeds maximum file size of %d Mb", a.filePath, a.maxFileSize)
			return nil, false, true
		}
	}

	// Sizing the buffer from the stat already taken above reads the file in one
	// pass. io.ReadAll would start at 512 bytes and repeatedly double, so every
	// classified file would cost a handful of allocations and copies instead.
	var buf bytes.Buffer
	if size > 0 && int64(int(size)) == size {
		buf.Grow(int(size) + bytes.MinRead)
	}
	if _, err := buf.ReadFrom(file); err != nil {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Error().Msgf("failed to analyze file: %s", err)
		return nil, false, false
	}
	return buf.Bytes(), true, false
}

func (a *analyzerInfo) persistWorkerState(content []byte, platform string) {
	if a.contentCache != nil && len(content) > 0 {
		a.contentCache.Store(a.filePath, content)
	}
	if a.filePlatformMap != nil {
		a.filePlatformMap.Store(a.filePath, platform)
	}
}

func isDockerfile(ctx context.Context, path string) bool {
	contextLogger := logger.FromContext(ctx)
	content, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		contextLogger.Error().Msgf("failed to analyze file: %s", err)
		return false
	}

	regexes := []*regexp.Regexp{
		regexp.MustCompile(`\s*FROM\s*`),
		regexp.MustCompile(`\s*RUN\s*`),
	}

	check := true

	for _, regex := range regexes {
		if !regex.Match(content) {
			check = false
			break
		}
	}

	return check
}

// overrides k8s match when all regexs passes for azureresourcemanager key and extension is set to json
func needsOverride(check bool, returnType, key, ext string) bool {
	if check && returnType == kubernetes && key == arm && ext == json {
		return true
	} else if check && returnType == kubernetes && (key == knative || key == crossplane) && (ext == yaml || ext == yml) {
		return true
	}
	return false
}

// classifyByContent determines the platform of a content-detected file (yaml,
// yml, json, sh) using the type regexes and the post-processing in
// checkReturnType. It returns the platform string (lowercased) or "" when none
// matches or the file is a non-Terraform JSON (which the scanner does not scan).
// typesFlag restricts the candidate platforms; pass nil or [""] to consider all.
func classifyByContent(ctx context.Context, path string, content []byte, ext string, typesFlag []string, hc *sync.Map) string {
	returnType := ""

	// Sort map so that CloudFormation (type that as less requireds) goes last
	keys := make([]string, 0, len(types))
	for k := range types {
		keys = append(keys, k)
	}

	if len(typesFlag) > 0 && typesFlag[0] != "" {
		keys = getKeysFromTypesFlag(typesFlag)
	}

	sort.Sort(sort.Reverse(sort.StringSlice(keys)))

	for _, key := range keys {
		if hints, ok := contentHints[key]; ok && !containsAny(content, hints) {
			continue
		}
		check := true
		for _, typeRegex := range types[key].regex {
			if !typeRegex.Match(content) {
				check = false
				break
			}
		}
		// If all regexs passed and there wasn't a type already assigned
		if check && returnType == "" {
			returnType = key
		} else if needsOverride(check, returnType, key, ext) {
			returnType = key
		}
	}

	endReturnType := checkReturnType(ctx, path, returnType, ext, content, hc)

	// Only process JSON files if they are Terraform plans
	// This will be the case until other platforms support json scanning
	if ext == json && (endReturnType != "terraform" || returnType == cdkTf) {
		return ""
	}

	return endReturnType
}

func containsAny(content []byte, needles [][]byte) bool {
	for _, needle := range needles {
		if bytes.Contains(content, needle) {
			return true
		}
	}
	return false
}

// ClassifyFile returns the platform a file would be classified as (lowercased,
// e.g. "ansible", "kubernetes", "terraform", "bicep"), or "" when undetermined.
// It mirrors the per-file detection used during analysis so callers (e.g. the
// parsing sink) can attribute each parsed document to its platform without
// re-running the full analyzer. content is the raw file bytes; typesFlag
// restricts candidate platforms (case-insensitive; pass nil to consider all).
// Passing the same platform set the analyzer used keeps the sink's
// classification consistent with the analyzer's. fsys is the filesystem used
// for extension detection; pass the in-memory FS for pushed content that never
// touches disk, or nil to default to the real disk.
func ClassifyFile(ctx context.Context, fsys vfs.FS, path string, content []byte, typesFlag []string) string {
	return classifyFile(ctx, fsys, path, content, typesFlag, nil)
}

// classifyFile is the internal implementation; hc is the per-scan helm cache
// (nil disables caching, which is safe for the server/sink path).
func classifyFile(ctx context.Context, fsys vfs.FS, path string, content []byte, typesFlag []string, hc *sync.Map) string {
	if fsys == nil {
		fsys = vfs.DiskFS{}
	}
	typesFlag = typesLower(typesFlag)
	ext, err := utils.GetExtensionWithFS(ctx, fsys, path)
	if err != nil {
		return ""
	}
	switch ext {
	case extDockerfile, nameDockerfile:
		return dockerfile
	case extPossibleDockerfile, extUbi8, extDebian:
		if isDockerfile(ctx, path) {
			return dockerfile
		}
		return ""
	case extTf, extTfvars:
		return terraform
	case extBicepFile:
		return bicep
	case extProto:
		return grpc
	case extCfg, extConf, extIni:
		return ansible
	case yaml, yml, json, sh:
		return classifyByContent(ctx, path, content, ext, typesFlag, hc)
	}
	return ""
}

// ClassifyParsedFile attributes a parsed file to its platform for payload
// bucketing. FileKind overrides extension/content detection for unambiguous
// types (Helm rendered manifests are Kubernetes, etc.). Returns "" when
// undetermined. platforms is the scan's effective platform set, forwarded to
// ClassifyFile so the sink classifies ambiguous files with the same candidate
// set the analyzer used (e.g. a Crossplane file is "kubernetes" in a default
// scan, "crossplane" only when Crossplane is enabled). fsys is forwarded for
// extension detection so the server's in-memory pushed content (not on disk) is
// classified correctly.
func ClassifyParsedFile(ctx context.Context, fsys vfs.FS, platforms []string, kind model.FileKind, path string, content []byte) string {
	if platform, ok := PlatformForKind(kind); ok {
		return platform
	}
	return ClassifyFile(ctx, fsys, path, content, platforms)
}

// PlatformForKind returns the fixed platform for kind when known.
func PlatformForKind(kind model.FileKind) (string, bool) {
	switch kind {
	case model.KindHELM:
		return kubernetes, true
	case model.KindTerraform, model.KindTerraformPlan:
		return terraform, true
	case model.KindDOCKER:
		return dockerfile, true
	case model.KindBICEP:
		return arm, true
	case model.KindPROTO:
		return grpc, true
	case model.KindINI, model.KindCFG:
		return ansible, true
	default:
		return "", false
	}
}

func checkReturnType(ctx context.Context, path, returnType, ext string, content []byte, hc *sync.Map) string {
	if returnType != "" {
		switch returnType {
		case cdkTf:
			return terraform
		case dependabot:
			return cicd
		case githubAction:
			return cicd
		}
		if utils.Contains(returnType, armRegexTypes) {
			return arm
		}
	} else if ext == yaml || ext == yml {
		if checkHelm(ctx, path, hc) {
			return kubernetes
		}
		platform := checkYamlPlatform(ctx, content, path)
		if platform != "" {
			return platform
		}
	}
	return returnType
}

// checkHelm reports whether the file belongs to a Helm chart by looking for a
// Chart.yaml in any ancestor directory, since templates can be nested below the
// chart root (e.g. templates/sub/ or charts/<subchart>/templates/).
// hc is the scan-scoped cache; when nil the lookup always hits the filesystem.
func checkHelm(ctx context.Context, path string, hc *sync.Map) bool {
	contextLogger := logger.FromContext(ctx)
	startDir := filepath.Dir(path)
	if hc != nil {
		if v, ok := hc.Load(startDir); ok {
			return v.(bool)
		}
	}

	// Every directory walked before the answer is known shares that answer, so
	// all of them are memoized. This keeps the total number of Chart.yaml probes
	// proportional to the number of directories in the repository rather than to
	// directories times their depth, and lets sibling subtrees reuse the walk.
	walked := []string{startDir}
	dir := startDir
	for {
		if hc != nil && dir != startDir {
			if v, ok := hc.Load(dir); ok {
				return storeHelmResults(hc, walked, v.(bool))
			}
		}
		_, err := os.Stat(filepath.Join(dir, "Chart.yaml"))
		if err == nil {
			return storeHelmResults(hc, walked, true)
		}
		if !errors.Is(err, os.ErrNotExist) {
			contextLogger.Error().Msgf("failed to check helm: %s", err)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return storeHelmResults(hc, walked, false)
		}
		dir = parent
		walked = append(walked, dir)
	}
}

func storeHelmResults(hc *sync.Map, dirs []string, result bool) bool {
	if hc == nil {
		return result
	}
	for _, dir := range dirs {
		hc.Store(dir, result)
	}
	return result
}

func checkYamlPlatform(ctx context.Context, content []byte, path string) string {
	// Ansible 'templates/' directories contain Jinja2 files; {{ }} syntax is invalid YAML.
	if isInsideAnsibleTemplatesDir(path) {
		return ""
	}

	contextLogger := logger.FromContext(ctx)

	content = utils.DecryptAnsibleVault(ctx, content, utils.GetVaultPassword())

	// A still-encrypted file has no readable content to classify, so it stays
	// unclassified even when it sits in a path that otherwise implies Ansible.
	if utils.IsAnsibleVaultEncrypted(content) {
		return ""
	}

	ansibleVarsPath := checkForAnsibleByPaths(path)
	if !ansibleVarsPath && !yamlRootHasAnyKey(content, yamlPlatformRootKeys...) {
		return ""
	}

	root, err := yamlDocumentRoot(content)
	if err != nil {
		contextLogger.Warn().Msgf("failed to parse yaml file (%s): %s", path, err)
		return ""
	}
	if root == nil {
		return ""
	}
	if ansibleVarsPath {
		if yamlRootIsMapping(root) {
			return ansible
		}
		return ""
	}

	if yamlMapKeyNode(root, listKeywordsGoogleDeployment[0]) != nil {
		return gdm
	}
	if ansibleFromYAMLNode(root) {
		return ansible
	}
	return ""
}

func checkForAnsibleByPaths(path string) bool {
	path = filepath.ToSlash(path)
	return strings.Contains(path, "/group_vars/") || strings.Contains(path, "/host_vars/")
}

// isInsideAnsibleTemplatesDir reports whether path is inside an Ansible templates directory.
// It requires a preceding "roles" or "ansible" path component to avoid false positives on
// non-Ansible repos that happen to have their own templates/ directories.
func isInsideAnsibleTemplatesDir(path string) bool {
	parts := strings.FieldsFunc(filepath.Clean(path), func(r rune) bool {
		if r > unicode.MaxLatin1 {
			return false
		}
		return os.IsPathSeparator(uint8(r))
	})
	seenSignal := false
	for _, part := range parts {
		if part == "ansible" || part == "roles" {
			seenSignal = true
		}
		if part == "templates" && seenSignal {
			return true
		}
	}
	return false
}

// computeValues computes expected Lines of Code to be scanned from locCount channel
// and creates the types and unwanted slices from the channels removing any duplicates.
func computeValues(types, unwanted chan string, locCount chan int) (typesS, unwantedS []string, locTotal int) {
	var val int
	unwantedSet := make(map[string]struct{})
	typeSet := make(map[string]struct{})
	for locCount != nil || unwanted != nil || types != nil {
		select {
		case i, ok := <-locCount:
			if ok {
				val += i
			} else {
				locCount = nil
			}
		case i, ok := <-unwanted:
			if ok {
				unwantedSet[i] = struct{}{}
			} else {
				unwanted = nil
			}
		case i, ok := <-types:
			if ok {
				typeSet[i] = struct{}{}
			} else {
				types = nil
			}
		}
	}
	typeSlice := make([]string, 0, len(typeSet))
	for k := range typeSet {
		typeSlice = append(typeSlice, k)
	}
	unwantedSlice := make([]string, 0, len(unwantedSet))
	for k := range unwantedSet {
		unwantedSlice = append(unwantedSlice, k)
	}
	return typeSlice, unwantedSlice, val
}

// getKeysFromTypesFlag gets all the regexes keys related to the types flag
func getKeysFromTypesFlag(typesFlag []string) []string {
	ks := make([]string, 0, len(types))
	for i := range typesFlag {
		t := typesFlag[i]

		if regexes, ok := supportedRegexes[t]; ok {
			ks = append(ks, regexes...)
		}
	}
	return ks
}

// expandPaths expands a slice of path expressions (which may include globs) into concrete paths.
//
// The nil/empty distinction in the return value is intentional and meaningful:
//   - nil input (or empty input) → nil output: signals "no restriction configured"
//   - non-empty input → non-nil output (possibly []string{}): signals "restriction is in
//     effect", even if all glob patterns matched nothing. Callers must treat a non-nil
//     empty result as "restrict to zero files", not as "no restriction".
func expandPaths(ctx context.Context, paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	expanded := make([]string, 0, len(paths))
	for _, p := range paths {
		exp, err := provider.GetExcludePaths(ctx, p)
		if err != nil {
			return nil, err
		}
		expanded = append(expanded, exp...)
	}
	return expanded, nil
}

// isIncludedFile returns true if path should be included given the onlyPaths restriction.
// onlyPaths must be the result of expandPaths:
//   - nil means no restriction was configured → include all files
//   - non-nil (even empty) means a restriction is in effect → only matching files pass
func isIncludedFile(path string, onlyPaths []string) bool {
	if onlyPaths == nil {
		return true
	}
	for _, p := range onlyPaths {
		if p == path || strings.HasPrefix(path, p+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

// isExcludedFile verifies if the path is in the pre-expanded exclude list
func isExcludedFile(path string, expandedExc []string) bool {
	for _, p := range expandedExc {
		if p == path {
			return true
		}
	}
	return false
}

func isConfigFile(path string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if suffix != "" && strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

// shouldConsiderGitIgnoreFile verifies if the scan should exclude the files according to the .gitignore file
func shouldConsiderGitIgnoreFile(ctx context.Context, path, gitIgnore string, excludeGitIgnoreFile bool) (hasGitIgnoreFileRes bool,
	gitIgnoreRes *gitIgnoreMatcher) {
	contextLogger := logger.FromContext(ctx)
	gitIgnorePath := filepath.ToSlash(filepath.Join(path, gitIgnore))
	_, err := os.Stat(gitIgnorePath)

	if !excludeGitIgnoreFile && err == nil && gitIgnore != "" {
		gitIgnore, _ := compileGitIgnoreFile(gitIgnorePath)
		if gitIgnore != nil {
			contextLogger.Info().Msgf(".gitignore file was found in '%s' and it will be used to automatically exclude paths", path)
			return true, gitIgnore
		}
	}
	return false, nil
}

func multiPlatformTypeCheck(typesSelected *[]string) {
	if utils.Contains("serverlessfw", *typesSelected) && !utils.Contains("cloudformation", *typesSelected) {
		*typesSelected = append(*typesSelected, "cloudformation")
	}
	if utils.Contains("knative", *typesSelected) && !utils.Contains("kubernetes", *typesSelected) {
		*typesSelected = append(*typesSelected, "kubernetes")
	}
}

func (a *analyzerInfo) isAvailableType(typeName string) bool {
	// no flag is set
	if len(a.typesFlag) == 1 && a.typesFlag[0] == "" {
		return true
	}
	// type flag is set
	return utils.Contains(typeName, a.typesFlag)
}

func typesLower(types []string) []string {
	out := make([]string, len(types))
	for i := range types {
		out[i] = strings.ToLower(types[i])
	}
	return out
}
