package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/config"
	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	ansibleConfigParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/ansible/ini/config"
	ansibleHostsParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/ansible/ini/hosts"
	bicepParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/bicep"
	buildahParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/buildah"
	dockerParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/docker"
	protoParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/grpc"
	jsonParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/json"
	terraformParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	cicdParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/cicd"
	yamlParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/default"
	"github.com/DataDog/datadog-iac-scanner/pkg/runner"
	scanUtils "github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/google/uuid"
	cli "github.com/urfave/cli/v3"
)

const (
	defaultRuleTestTimeoutSecs      = 60
	defaultRuleTestMaxResolverDepth = 15
	fixtureDirPerm                  = 0700
	fixtureFilePerm                 = 0600
)

// resultShape is the per-rule Rego result contract checked during tests.
var resultShape = struct {
	Required     []string
	ResourceKeys []string
}{
	Required: []string{
		"documentId",
		"searchKey",
		"issueType",
		"keyExpectedValue",
		"keyActualValue",
	},
	ResourceKeys: []string{"resourceType", "resourceName"},
}

// allowedIssueTypes is the set of issueType values a rule result may emit.
var allowedIssueTypes = map[string]struct{}{
	"MissingAttribute":   {},
	"IncorrectValue":     {},
	"RedundantAttribute": {},
}

// platformsRequiringResourceKeys is the set of platforms whose Rego results
// must include resourceType and resourceName.
var platformsRequiringResourceKeys = map[string]struct{}{
	"terraform":               {},
	"cloudformation":          {},
	"ansible":                 {},
	"kubernetes":              {},
	"k8s":                     {},
	"googledeploymentmanager": {},
	"crossplane":              {},
	"azureresourcemanager":    {},
	"pulumi":                  {},
}

// ruleFinding is one result emitted by a rule's DatadogPolicy evaluation.
type ruleFinding struct {
	QueryName string
	Severity  string
	Line      int
	FileName  string
}

type ruleOutcome struct {
	id         string
	mismatches []string
}

var testRulesAction = &cli.Command{
	Name:  "test-rules",
	Usage: "runs the rule tests stored in the Datadog backend against the local engine",
	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:  "rule",
			Usage: "only test rules with these IDs or names (default: all rules)",
		},
		&cli.StringSliceFlag{
			Name:    "type",
			Aliases: []string{"t"},
			Usage:   "only test rules for these platforms",
		},
	},
	Action: runTestRules,
}

func runTestRules(ctx context.Context, c *cli.Command) error {
	client := datadog.NewDatadogClient()
	ruleset, err := client.GetDefaultRulesetWithTests(ctx)
	if err != nil {
		return fmt.Errorf("fetching rules with tests: %w", err)
	}

	ruleFilter := c.StringSlice("rule")
	platformFilter := c.StringSlice("type")

	var results []ruleOutcome
	allPass := true

	for _, rule := range ruleset.Rules {
		if !shouldRunRule(rule, platformFilter, ruleFilter) {
			continue
		}

		mismatches, err := runRule(ctx, rule)
		if err != nil {
			return fmt.Errorf("testing rule %s: %w", rule.ID, err)
		}
		results = append(results, ruleOutcome{id: rule.ID, mismatches: mismatches})
		allPass = allPass && len(mismatches) == 0
	}

	return finishTests(results, allPass)
}

func shouldRunRule(rule *datadog.Rule, platformFilter, ruleFilter []string) bool {
	if !rule.IsPublished || rule.Tests == nil {
		return false
	}
	if len(platformFilter) > 0 && !slices.ContainsFunc(platformFilter, func(p string) bool {
		return strings.EqualFold(p, rule.Platform)
	}) {
		return false
	}
	if len(ruleFilter) == 0 {
		return true
	}
	legacyID := ""
	if rule.LegacyId != nil {
		legacyID = *rule.LegacyId
	}
	return slices.Contains(ruleFilter, rule.ID) || slices.Contains(ruleFilter, legacyID)
}

func finishTests(results []ruleOutcome, allPass bool) error {
	if allPass {
		if len(results) == 0 {
			fmt.Println("No rules with tests were found")
			os.Exit(1)
		}
		fmt.Printf("PASS: %s\n", plural("%d rule", "%d rules", len(results)))
		return nil
	}

	var failed, passed int
	for _, r := range results {
		if len(r.mismatches) == 0 {
			passed++
			fmt.Printf("PASS: %s\n", r.id)
		} else {
			failed++
			fmt.Printf("FAIL: %s\n", r.id)
			for _, m := range r.mismatches {
				fmt.Printf("  %s\n", m)
			}
		}
	}
	fmt.Printf("FAIL: %s, %s\n",
		plural("%d rule failed", "%d rules failed", failed),
		plural("%d rule passed", "%d rules passed", passed))
	os.Exit(1)
	return nil
}

// runRule materializes a rule's fixtures into a temp directory and runs them.
func runRule(ctx context.Context, rule *datadog.Rule) ([]string, error) {
	// Bound each rule's test run so a non-terminating or pathologically slow rule
	// is canceled instead of hanging CI. rego eval runs on this context, so the
	// deadline propagates into the engine without any engine-level timeout knob.
	ctx, cancel := context.WithTimeout(ctx, defaultRuleTestTimeoutSecs*time.Second)
	defer cancel()

	tmpDir, err := os.MkdirTemp("", "iac-rule-test-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir) // nolint:errcheck

	var positiveFiles, negativeFiles []string
	for _, tf := range rule.Tests.Files {
		dest := filepath.Join(tmpDir, filepath.FromSlash(tf.FileName))
		if err := os.MkdirAll(filepath.Dir(dest), fixtureDirPerm); err != nil {
			return nil, err
		}
		if err := os.WriteFile(dest, tf.Content, fixtureFilePerm); err != nil {
			return nil, err
		}
		base := filepath.Base(tf.FileName)
		switch {
		case strings.HasPrefix(base, "positive"):
			positiveFiles = append(positiveFiles, dest)
		case strings.HasPrefix(base, "negative"):
			negativeFiles = append(negativeFiles, dest)
		}
	}

	if len(positiveFiles) == 0 && len(negativeFiles) == 0 {
		return nil, nil
	}

	expected := make([]ruleFinding, len(rule.Tests.Expected))
	for i, ef := range rule.Tests.Expected {
		expected[i] = ruleFinding{
			QueryName: ef.ShortDescription,
			Severity:  ef.Severity,
			Line:      ef.Line,
			FileName:  ef.FileName,
		}
	}

	query := source.ConvertRule(rule)

	var mismatches []string

	positiveGot, positiveShape, err := runFiles(ctx, tmpDir, rule.ID, &query, positiveFiles)
	if err != nil {
		return nil, err
	}
	negativeGot, negativeShape, err := runFiles(ctx, tmpDir, rule.ID, &query, negativeFiles)
	if err != nil {
		return nil, err
	}

	mismatches = append(mismatches, positiveShape...)
	mismatches = append(mismatches, negativeShape...)
	mismatches = append(mismatches, compareFindings(expected, positiveGot)...)
	mismatches = append(mismatches, compareFindings([]ruleFinding{}, negativeGot)...)

	return mismatches, nil
}

// runFiles evaluates the rule against the given files and returns findings
// plus any result-shape errors.
func runFiles(
	ctx context.Context,
	rootPath, ruleID string,
	query *model.QueryMetadata,
	files []string,
) ([]ruleFinding, []string, error) {
	var allFiles model.FileMetadatas
	platformStr, _ := query.Metadata["platform"].(string)
	for _, f := range files {
		parsed, err := parseFixtureFile(ctx, rootPath, f, platformStr)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing %s: %w", f, err)
		}
		allFiles = append(allFiles, parsed...)
	}

	var shapeErrs []string
	builder := wrapShapeValidator(
		strings.ToLower(platformStr),
		ruleID,
		&shapeErrs,
	)

	inspector, err := engine.NewInspector(ctx,
		&singleRuleSource{query: query},
		builder,
		&noopTracker{},
		&source.QueryInspectorParameters{
			FlagEvaluator: featureflags.NewLocalEvaluator(),
		},
		map[string]config.IacRuleConfig{},
		rootPath,
		false,
		false,
		0,
		featureflags.NewLocalEvaluator(),
	)
	if err != nil {
		return nil, nil, err
	}

	vulns, err := inspector.Inspect(ctx, "test", allFiles, []string{platformStr})
	if err != nil {
		return nil, nil, err
	}

	out := make([]ruleFinding, len(vulns))
	for i := range vulns {
		v := vulns[i]
		out[i] = ruleFinding{
			QueryName: v.QueryName,
			Severity:  string(v.Severity),
			Line:      v.Line,
			FileName:  filepath.Base(v.FileName),
		}
	}
	return out, shapeErrs, nil
}

func wrapShapeValidator(
	platform string,
	ruleID string,
	errs *[]string,
) engine.VulnerabilityBuilder {
	return func(ctx context.Context, qCtx *engine.QueryContext, tracker engine.Tracker, v interface{},
		dl *detector.DetectLine, useOldSeverities bool, queryDuration time.Duration) (*model.Vulnerability, error) {
		if m, ok := v.(map[string]interface{}); ok {
			*errs = append(*errs, validateResultShape(m, platform, ruleID)...)
		}
		return engine.DefaultVulnerabilityBuilder(ctx, qCtx, tracker, v, dl, useOldSeverities, queryDuration)
	}
}

func validateResultShape(m map[string]interface{}, platform, ruleID string) []string {
	var errs []string
	for _, key := range resultShape.Required {
		if _, ok := m[key]; !ok {
			errs = append(errs, fmt.Sprintf("Result missing required field %q", key))
		}
	}
	if _, ok := platformsRequiringResourceKeys[platform]; ok {
		for _, key := range resultShape.ResourceKeys {
			if _, ok := m[key]; !ok {
				errs = append(errs, fmt.Sprintf("Result missing required field %q for platform %q in rule %s", key, platform, ruleID))
			}
		}
	}
	_, hasRemediation := m["remediation"]
	_, hasRemediationType := m["remediationType"]
	if hasRemediation != hasRemediationType {
		errs = append(errs, "Result has remediation/remediationType only on one side; both must be set together")
	}
	if issueType, _ := m["issueType"].(string); issueType != "" {
		if _, ok := allowedIssueTypes[issueType]; !ok {
			errs = append(errs, fmt.Sprintf("Result issueType %q is not in the allowed set", issueType))
		}
	}
	return errs
}

// compareFindings returns mismatch messages between expected and actual findings.
// An empty FileName in an expected finding acts as a wildcard.
func compareFindings(expected, got []ruleFinding) []string {
	remaining := slices.Clone(got)

	sorted := slices.Clone(expected)
	slices.SortStableFunc(sorted, func(a, b ruleFinding) int {
		if (a.FileName == "") == (b.FileName == "") {
			return 0
		}
		if a.FileName != "" {
			return -1
		}
		return 1
	})

	var mismatches []string
	for _, exp := range sorted {
		idx := slices.IndexFunc(remaining, func(g ruleFinding) bool {
			return findingsMatch(exp, g)
		})
		if idx == -1 {
			mismatches = append(mismatches, fmt.Sprintf("Missing expected: %#v", exp))
		} else {
			remaining = slices.Delete(remaining, idx, idx+1)
		}
	}
	for _, g := range remaining {
		mismatches = append(mismatches, fmt.Sprintf("Unexpected finding: %#v", g))
	}
	return mismatches
}

func findingsMatch(exp, got ruleFinding) bool {
	return exp.QueryName == got.QueryName &&
		exp.Severity == got.Severity &&
		exp.Line == got.Line &&
		(exp.FileName == "" || exp.FileName == got.FileName)
}

func parseFixtureFile(ctx context.Context, tmpRoot, filePath, platform string) (model.FileMetadatas, error) {
	cleanRoot := filepath.Clean(tmpRoot)
	cleanPath := filepath.Clean(filePath)
	rel, err := filepath.Rel(cleanRoot, cleanPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return nil, fmt.Errorf("test file path %q escapes fixture root", filePath)
	}

	content, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, err
	}

	ps, err := getFixtureParsers(ctx)
	if err != nil {
		return nil, err
	}

	var files model.FileMetadatas
	for _, p := range ps {
		if !p.Parsers.SupportedTypes()[normalizePlatform(platform)] {
			continue
		}
		docs, _ := p.Parse(ctx, cleanPath, content, true, false, defaultRuleTestMaxResolverDepth)
		for _, doc := range docs.Docs {
			files = append(files, &model.FileMetadata{
				ID:                uuid.NewString(),
				ScanID:            "test",
				Document:          runner.PrepareScanDocument(ctx, doc, docs.Kind),
				LineInfoDocument:  doc,
				OriginalData:      docs.Content,
				Kind:              docs.Kind,
				FilePath:          cleanPath,
				ResolvedFiles:     docs.ResolvedFiles,
				LinesOriginalData: scanUtils.SplitLines(docs.Content),
			})
		}
	}
	return files, nil
}

func normalizePlatform(platform string) string {
	if strings.EqualFold(platform, "k8s") {
		return "kubernetes"
	}
	return strings.ToLower(platform)
}

var (
	fixtureParsersOnce sync.Once
	fixtureParsers     []*parser.Parser
	fixtureParsersErr  error
)

func getFixtureParsers(ctx context.Context) ([]*parser.Parser, error) {
	fixtureParsersOnce.Do(func() {
		fixtureParsers, fixtureParsersErr = parser.NewBuilder(ctx).
			Add(&jsonParser.Parser{}).
			Add(&yamlParser.Parser{}).
			Add(terraformParser.NewDefault()).
			Add(&bicepParser.Parser{}).
			Add(&cicdParser.Parser{}).
			Add(&dockerParser.Parser{}).
			Add(&protoParser.Parser{}).
			Add(&buildahParser.Parser{}).
			Add(&ansibleConfigParser.Parser{}).
			Add(&ansibleHostsParser.Parser{}).
			Build([]string{""}, []string{""})
	})
	return fixtureParsers, fixtureParsersErr
}

type singleRuleSource struct {
	query *model.QueryMetadata
}

func (s *singleRuleSource) GetQueries(_ context.Context, _ *source.QueryInspectorParameters) ([]model.QueryMetadata, error) {
	return []model.QueryMetadata{*s.query}, nil
}

func (s *singleRuleSource) GetQueryLibrary(_ context.Context, platform string) (source.RegoLibraries, error) {
	// Import assets here to avoid a circular init between the scanner packages.
	// The embedded libraries live in the assets package and are needed for evaluation.
	from := source.NewFilesystemSource(
		context.Background(),
		[]string{""},
		[]string{strings.ToLower(platform)},
		[]string{""},
		"./assets/libraries",
		true,
	)
	return from.GetQueryLibrary(context.Background(), platform)
}

type noopTracker struct{}

func (t *noopTracker) TrackQueryLoad(int)      {}
func (t *noopTracker) TrackQueryExecuting(int) {}
func (t *noopTracker) TrackQueryExecution(int) {}
func (t *noopTracker) FailedDetectLine()       {}
func (t *noopTracker) GetOutputLines() int     { return 0 }
