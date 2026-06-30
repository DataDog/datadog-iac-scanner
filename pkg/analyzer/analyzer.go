/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package analyzer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/DataDog/datadog-iac-scanner/internal/metrics"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/provider"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/pkg/errors"
	ignore "github.com/sabhiram/go-gitignore"

	yamlParser "gopkg.in/yaml.v3"
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
	queryRegexPathsAnsible                          = regexp.MustCompile(fmt.Sprintf(`^.*?%s(?:group|host)_vars%s.*$`, regexp.QuoteMeta(string(os.PathSeparator)), regexp.QuoteMeta(string(os.PathSeparator)))) //nolint:lll
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
	extTfvars             = "tfvars"
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
	typesFlag []string
	filePath  string
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

var defaultConfigFiles = []string{"pnpm-lock.yaml"}

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
		if _, err := os.Stat(path); err != nil {
			return returnAnalyzedPaths, errors.Wrap(err, "failed to analyze path")
		}
		if err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if path == gitDir {
				a.Exc = append(a.Exc, path)
				return filepath.SkipDir
			}

			ext, errExt := utils.GetExtension(ctx, path)
			if errExt == nil {
				trimmedPath, err := filepath.Rel(a.RepoPath, path)
				if err != nil {
					return err
				}
				ignoreFiles = a.checkIgnore(ctx, info.Size(), hasGitIgnoreFile, gitIgnore, path, trimmedPath, ignoreFiles)

				if isConfigFile(ctx, path, defaultConfigFiles) {
					projectConfigFiles = append(projectConfigFiles, path)
					a.Exc = append(a.Exc, path)
				}

				if _, ok := possibleFileTypes[ext]; ok && !isExcludedFile(path, a.Exc) && isIncludedFile(path, a.Only) {
					files = append(files, path)
				}
			}
			return nil
		}); err != nil {
			contextLogger.Error().Msgf("failed to analyze path %s: %s", path, err)
		}
	}

	// unwanted is the channel shared by the workers that contains the unwanted files that the parser will ignore
	unwanted := make(chan string, len(files))

	typesFlag := typesLower(a.Types)

	// Detect each file's type with a bounded worker pool. File-type detection
	// reads file content (I/O-bound), so it does not consume the shared CPU
	// budget and fans out wider than the core count (same [min,max] bounds as the
	// filesystem reader). Workers write into the results/unwanted/locCount
	// channels, which computeValues drains concurrently below; the channels are
	// closed once all files are processed.
	go func() {
		_ = utils.ForEach(ctx, files, utils.PoolOptions{MinWorkers: utils.IOMinWorkers, MaxWorkers: utils.IOMaxWorkers},
			func(ctx context.Context, filePath string, _ int) error {
				analyzerInfo := &analyzerInfo{
					typesFlag: typesFlag,
					filePath:  filePath,
				}
				analyzerInfo.worker(ctx, results, unwanted, locCount)
				return nil
			})
		close(unwanted)
		close(results)
		close(locCount)
	}()

	availableTypes, unwantedPaths, loc := computeValues(results, unwanted, locCount)
	multiPlatformTypeCheck(&availableTypes)
	unwantedPaths = append(unwantedPaths, ignoreFiles...)
	unwantedPaths = append(unwantedPaths, projectConfigFiles...)
	returnAnalyzedPaths.Types = availableTypes
	returnAnalyzedPaths.Exc = unwantedPaths
	returnAnalyzedPaths.ExpectedLOC = loc
	return returnAnalyzedPaths, nil
}

// worker determines the type of the file by ext (dockerfile and terraform)/content and
// writes the answer to the results channel
// if no types were found, the worker will write the path of the file in the unwanted channel
func (a *analyzerInfo) worker(ctx context.Context, results, unwanted chan<- string, locCount chan<- int) {
	contextLogger := logger.FromContext(ctx)
	ext, errExt := utils.GetExtension(ctx, a.filePath)
	if errExt != nil {
		return
	}

	linesCount, _ := utils.LineCounter(ctx, a.filePath)

	var content []byte
	if ext == yaml || ext == yml || ext == json || ext == sh {
		var err error
		content, err = os.ReadFile(a.filePath)
		if err != nil {
			contextLogger.Error().Msgf("failed to analyze file: %s", err)
			return
		}
	}

	platform := ClassifyFile(ctx, vfs.DiskFS{}, a.filePath, content, a.typesFlag)
	if platform == "" {
		unwanted <- a.filePath
		return
	}
	if !a.isAvailableType(platform) {
		// Content-detected files that do not match the requested platforms are
		// excluded; extension-only types (e.g. .tf) are ignored silently.
		if ext == yaml || ext == yml || ext == json || ext == sh {
			unwanted <- a.filePath
		}
		return
	}
	results <- platform
	locCount <- linesCount
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
func classifyByContent(ctx context.Context, path string, content []byte, ext string, typesFlag []string) string {
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

	endReturnType := checkReturnType(ctx, path, returnType, ext, content)

	// Only process JSON files if they are Terraform plans
	// This will be the case until other platforms support json scanning
	if ext == json && (endReturnType != "terraform" || returnType == cdkTf) {
		return ""
	}

	return endReturnType
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
		return classifyByContent(ctx, path, content, ext, typesFlag)
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
	switch kind {
	case model.KindHELM:
		return kubernetes
	case model.KindTerraform, model.KindTerraformPlan:
		return terraform
	case model.KindDOCKER:
		return dockerfile
	case model.KindBICEP:
		return arm
	case model.KindPROTO:
		return grpc
	case model.KindINI, model.KindCFG:
		return ansible
	default:
		return ClassifyFile(ctx, fsys, path, content, platforms)
	}
}

func checkReturnType(ctx context.Context, path, returnType, ext string, content []byte) string {
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
		if checkHelm(ctx, path) {
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
func checkHelm(ctx context.Context, path string) bool {
	contextLogger := logger.FromContext(ctx)
	dir := filepath.Dir(path)
	for {
		_, err := os.Stat(filepath.Join(dir, "Chart.yaml"))
		if err == nil {
			return true
		}
		if !errors.Is(err, os.ErrNotExist) {
			contextLogger.Error().Msgf("failed to check helm: %s", err)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

func checkYamlPlatform(ctx context.Context, content []byte, path string) string {
	// Ansible 'templates/' directories contain Jinja2 files; {{ }} syntax is invalid YAML.
	if isInsideAnsibleTemplatesDir(path) {
		return ""
	}

	contextLogger := logger.FromContext(ctx)

	content = utils.DecryptAnsibleVault(ctx, content, utils.GetVaultPassword())

	if utils.IsAnsibleVaultEncrypted(content) {
		return ""
	}

	// Parse as Node to manually call Datadog's version of UnmarshalYAML with context
	var node yamlParser.Node
	if err := yamlParser.Unmarshal(content, &node); err != nil {
		contextLogger.Warn().Msgf("failed to parse yaml file (%s): %s", path, err)
		return ""
	}

	// Get the yaml content in node
	contentNode := &node
	if node.Kind == yamlParser.DocumentNode && len(node.Content) > 0 {
		contentNode = node.Content[0]
	}

	// A scalar root means the document is empty/null (e.g. a comment-only vars file).
	// No platform can be detected; skip silently.
	if contentNode.Kind == yamlParser.ScalarNode {
		return ""
	}

	var yamlContent model.Document
	if err := yamlContent.UnmarshalYAML(ctx, contentNode, nil); err != nil {
		contextLogger.Warn().Msgf("failed to unmarshal yaml file (%s): %s", path, err)
		return ""
	}

	// check if it is google deployment manager platform
	for _, keyword := range listKeywordsGoogleDeployment {
		if _, ok := yamlContent[keyword]; ok {
			return gdm
		}
	}

	// check if the file contains some keywords related with Ansible
	if checkForAnsible(yamlContent) {
		return ansible
	}
	// check if the file contains some keywords related with Ansible Host
	if checkForAnsibleHost(yamlContent) {
		return ansible
	}
	// add for yaml files contained at paths (group_vars, host_vars) related with ansible
	if checkForAnsibleByPaths(path) {
		return ansible
	}
	return ""
}

func checkForAnsibleByPaths(path string) bool {
	return queryRegexPathsAnsible.MatchString(path)
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

func checkForAnsible(yamlContent model.Document) bool {
	isAnsible := false
	if play := yamlContent[playBooks]; play != nil {
		if listOfPlayBooks, ok := play.([]interface{}); ok {
			for _, value := range listOfPlayBooks {
				castingValue, ok := value.(map[string]interface{})
				if ok {
					for _, keyword := range listKeywordsAnsible {
						if _, ok := castingValue[keyword]; ok {
							isAnsible = true
						}
					}
				}
			}
		}
	}
	return isAnsible
}

func checkForAnsibleHost(yamlContent model.Document) bool {
	isAnsible := false
	for _, ansibleDefault := range ansibleHost {
		if hosts := yamlContent[ansibleDefault]; hosts != nil {
			if listHosts, ok := hosts.(map[string]interface{}); ok {
				for _, value := range listKeywordsAnsibleHots {
					if host := listHosts[value]; host != nil {
						isAnsible = true
					}
				}
			}
		}
	}
	return isAnsible
}

// computeValues computes expected Lines of Code to be scanned from locCount channel
// and creates the types and unwanted slices from the channels removing any duplicates
func computeValues(types, unwanted chan string, locCount chan int) (typesS, unwantedS []string, locTotal int) {
	var val int
	unwantedSlice := make([]string, 0)
	typeSlice := make([]string, 0)
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
				if !utils.Contains(i, unwantedSlice) {
					unwantedSlice = append(unwantedSlice, i)
				}
			} else {
				unwanted = nil
			}
		case i, ok := <-types:
			if ok {
				if !utils.Contains(i, typeSlice) {
					typeSlice = append(typeSlice, i)
				}
			} else {
				types = nil
			}
		}
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

func isDeadSymlink(path string) bool {
	fileInfo, _ := os.Stat(path)
	return fileInfo == nil
}

func isConfigFile(ctx context.Context, path string, exc []string) bool {
	contextLogger := logger.FromContext(ctx)
	for i := range exc {
		exclude, err := provider.GetExcludePaths(ctx, exc[i])
		if err != nil {
			contextLogger.Err(err).Msg("failed to get exclude paths")
		}
		for j := range exclude {
			fileInfo, _ := os.Stat(path)
			if fileInfo != nil && fileInfo.IsDir() {
				continue
			}

			if len(path)-len(exclude[j]) > 0 && path[len(path)-len(exclude[j]):] == exclude[j] && exclude[j] != "" {
				contextLogger.Info().Msgf("Excluded file %s from analyzer", path)
				return true
			}
		}
	}
	return false
}

// shouldConsiderGitIgnoreFile verifies if the scan should exclude the files according to the .gitignore file
func shouldConsiderGitIgnoreFile(ctx context.Context, path, gitIgnore string, excludeGitIgnoreFile bool) (hasGitIgnoreFileRes bool,
	gitIgnoreRes *ignore.GitIgnore) {
	contextLogger := logger.FromContext(ctx)
	gitIgnorePath := filepath.ToSlash(filepath.Join(path, gitIgnore))
	_, err := os.Stat(gitIgnorePath)

	if !excludeGitIgnoreFile && err == nil && gitIgnore != "" {
		gitIgnore, _ := ignore.CompileIgnoreFile(gitIgnorePath)
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

func (a *Analyzer) checkIgnore(ctx context.Context, fileSize int64, hasGitIgnoreFile bool,
	gitIgnore *ignore.GitIgnore,
	fullPath string, trimmedPath string, ignoreFiles []string) []string {
	contextLogger := logger.FromContext(ctx)
	exceededFileSize := a.MaxFileSize >= 0 && float64(fileSize)/float64(sizeMb) > float64(a.MaxFileSize)

	if (hasGitIgnoreFile && gitIgnore.MatchesPath(trimmedPath)) || isDeadSymlink(fullPath) || exceededFileSize {
		ignoreFiles = append(ignoreFiles, fullPath)
		a.Exc = append(a.Exc, fullPath)

		if exceededFileSize {
			contextLogger.Warn().Msgf("file %s exceeds maximum file size of %d Mb", fullPath, a.MaxFileSize)
		}
	}
	return ignoreFiles
}

func typesLower(types []string) []string {
	out := make([]string, len(types))
	for i := range types {
		out[i] = strings.ToLower(types[i])
	}
	return out
}
