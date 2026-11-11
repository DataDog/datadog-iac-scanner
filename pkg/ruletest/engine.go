package ruletest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/config"
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
	dockerComposeParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/dockercompose"
	"github.com/DataDog/datadog-iac-scanner/pkg/runner"
	scanUtils "github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/google/uuid"
)

const maxResolverDepth = 15

type evaluator struct {
	query                model.QueryMetadata
	libraries            source.QueriesSource
	resourceKeyPlatforms []string
	tmpDir               string
	roots                int
}

// evalRoots evaluates each root in its own directory and returns the findings
// of all roots followed by the result-contract errors and each distinct query
// error.
func (ev *evaluator) evalRoots(ctx context.Context, roots []root, arguments map[string]any) ([]Finding, []Mismatch, error) {
	var findings []Finding
	var errs []Mismatch
	queryErrs := map[string]bool{}
	for _, r := range roots {
		dir := filepath.Join(ev.tmpDir, strconv.Itoa(ev.roots))
		ev.roots++
		paths, err := r.write(dir)
		if err != nil {
			return nil, nil, err
		}
		got, rootErrs, err := ev.eval(ctx, dir, paths, arguments)
		if err != nil {
			return nil, nil, err
		}
		findings = append(findings, got...)
		for _, e := range rootErrs {
			if e.Kind == QueryFailed {
				if queryErrs[e.Message] {
					continue
				}
				queryErrs[e.Message] = true
			}
			errs = append(errs, e)
		}
	}
	return findings, errs, nil
}

func (ev *evaluator) eval(ctx context.Context, dir string, paths []string, arguments map[string]any) ([]Finding, []Mismatch, error) {
	vulns, errs, err := ev.inspect(ctx, dir, paths, arguments)
	if err != nil {
		return nil, nil, err
	}
	out := make([]Finding, len(vulns))
	for i := range vulns {
		out[i] = testFinding(&vulns[i])
	}
	return out, errs, nil
}

func testFinding(v *model.Vulnerability) Finding {
	f := Finding{
		QueryName: v.QueryName,
		Severity:  string(v.Severity),
		Line:      v.Line,
		FileName:  filepath.Base(v.FileName),
	}
	// Instantiated module findings are reported at the call site, as in SARIF.
	if attr := v.ModuleAttribution; attr != nil && attr.CallSite.Filename != "" {
		f.Line = attr.CallSite.LineStart
		f.FileName = filepath.Base(attr.CallSite.Filename)
	}
	return f
}

func (ev *evaluator) inspect(
	ctx context.Context, dir string, paths []string, arguments map[string]any,
) ([]model.Vulnerability, []Mismatch, error) {
	platform, _ := ev.query.Metadata["platform"].(string)
	var files model.FileMetadatas
	for _, p := range paths {
		parsed, err := parseFixtureFile(ctx, p, platform)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing %s: %w", p, err)
		}
		files = append(files, parsed...)
	}

	var errs []Mismatch
	ruleID, _ := ev.query.Metadata["id"].(string)
	requireResourceKeys := slices.ContainsFunc(ev.resourceKeyPlatforms, func(p string) bool {
		return strings.EqualFold(p, platform)
	})
	builder := func(ctx context.Context, qCtx *engine.QueryContext, tracker engine.Tracker, v any,
		dl *detector.DetectLine, useOldSeverities bool, queryDuration time.Duration) (*model.Vulnerability, error) {
		if m, ok := v.(map[string]any); ok {
			for _, msg := range validateResult(m, platform, ruleID, requireResourceKeys) {
				errs = append(errs, Mismatch{Kind: InvalidResult, Message: msg})
			}
		}
		return engine.DefaultVulnerabilityBuilder(ctx, qCtx, tracker, v, dl, useOldSeverities, queryDuration)
	}

	inspector, err := engine.NewInspector(ctx,
		&singleRuleSource{query: ev.query, libraries: ev.libraries},
		builder,
		&noopTracker{},
		&source.QueryInspectorParameters{
			FlagEvaluator: featureflags.NewLocalEvaluator(),
		},
		ruleConfigs(ruleID, arguments),
		dir,
		false,
		false,
		0,
		featureflags.NewLocalEvaluator(),
		vfs.DiskFS{},
		// Every root of a rule reuses the rule's compiled query.
		true,
	)
	if err != nil {
		return nil, nil, err
	}

	vulns, err := inspector.Inspect(ctx, "test", files, []string{platform})
	if err != nil {
		return nil, nil, err
	}
	for _, qErr := range inspector.GetFailedQueries() {
		errs = append(errs, Mismatch{Kind: QueryFailed, Message: sortErrorLines(qErr.Error())})
	}
	return vulns, errs, nil
}

// sortErrorLines orders the lines after the first one of a multi-error
// message, which Rego compilation lists in no fixed order.
func sortErrorLines(msg string) string {
	lines := strings.Split(msg, "\n")
	if len(lines) > 2 {
		slices.Sort(lines[1:])
	}
	return strings.Join(lines, "\n")
}

func ruleConfigs(ruleID string, arguments map[string]any) map[string]config.IacRuleConfig {
	if len(arguments) == 0 || ruleID == "" {
		return map[string]config.IacRuleConfig{}
	}
	return map[string]config.IacRuleConfig{ruleID: {Arguments: arguments}}
}

func parseFixtureFile(ctx context.Context, filePath, platform string) (model.FileMetadatas, error) {
	content, err := os.ReadFile(filepath.Clean(filePath))
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
		docs, _ := p.Parse(ctx, filePath, content, true, false, maxResolverDepth)
		// docs.Content is identical for every document of the file.
		linesOriginalData := scanUtils.SplitLines(docs.Content)
		for _, doc := range docs.Docs {
			files = append(files, &model.FileMetadata{
				ID:                uuid.NewString(),
				ScanID:            "test",
				Document:          runner.PrepareScanDocument(ctx, doc, docs.Kind),
				LineInfoDocument:  doc,
				OriginalData:      docs.Content,
				Kind:              docs.Kind,
				FilePath:          filePath,
				ResolvedFiles:     docs.ResolvedFiles,
				LinesOriginalData: linesOriginalData,
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
	errFixtureParsers  error
)

func getFixtureParsers(ctx context.Context) ([]*parser.Parser, error) {
	fixtureParsersOnce.Do(func() {
		fixtureParsers, errFixtureParsers = parser.NewBuilder(ctx).
			Add(&jsonParser.Parser{}).
			Add(&yamlParser.Parser{}).
			Add(dockerComposeParser.NewDefaultWithFS(nil)).
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
	return fixtureParsers, errFixtureParsers
}

// singleRuleSource serves one rule and delegates libraries.
type singleRuleSource struct {
	query     model.QueryMetadata
	libraries source.QueriesSource
}

func (s *singleRuleSource) GetQueries(_ context.Context, _ *source.QueryInspectorParameters) ([]model.QueryMetadata, error) {
	return []model.QueryMetadata{s.query}, nil
}

func (s *singleRuleSource) GetQueryLibrary(ctx context.Context, platform string) (source.RegoLibraries, error) {
	return s.libraries.GetQueryLibrary(ctx, platform)
}

type noopTracker struct{}

func (t *noopTracker) TrackQueryLoad(int)       {}
func (t *noopTracker) TrackQueryExecuting(int)  {}
func (t *noopTracker) TrackQueryExecution(int)  {}
func (t *noopTracker) FailedDetectLine()        {}
func (t *noopTracker) FailedLineInfoDocument()  {}
func (t *noopTracker) SkippedSupersededResult() {}
func (t *noopTracker) GetOutputLines() int      { return 0 }
