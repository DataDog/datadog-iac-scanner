package kustomize

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/resolver/sandbox"
	"sigs.k8s.io/kustomize/api/provider"
	"sigs.k8s.io/kustomize/api/resmap"
	"sigs.k8s.io/kustomize/api/resource"
)

// Options configures the Kustomize preprocessor.
type Options struct {
	RepoRoot           string
	AllowHelmInflation bool
	RenderTimeout      time.Duration
	HelmIncludeCRDs    bool
	// MaxFetchBytes: cap bytes under the resolve scratch dir (0 = unlimited).
	MaxFetchBytes int64
	// StrictLoad: RootOnly (stricter) vs None (overlay-friendly, wider reads).
	StrictLoad bool
}

// Resolver renders kustomization directories to concrete manifests.
type Resolver struct {
	opts Options
}

// NewResolver constructs a Kustomize preprocessor.
func NewResolver(opts Options) *Resolver {
	if opts.RenderTimeout <= 0 {
		opts.RenderTimeout = 60 * time.Second
	}
	return &Resolver{opts: opts}
}

// Name implements resolver.Preprocessor.
func (r *Resolver) Name() string {
	return "kustomize"
}

// Detect implements resolver.Preprocessor.
func (r *Resolver) Detect(path string) (model.FileKind, bool) {
	return Detect(path)
}

// SupportedTypes implements resolver.Preprocessor.
func (r *Resolver) SupportedTypes() []model.FileKind {
	return []model.FileKind{model.KindKUSTOMIZE}
}

// Resolve runs kustomize build for the given root directory.
func (r *Resolver) Resolve(ctx context.Context, rootDir string) (model.ResolvedFiles, error) {
	contextLogger := logger.FromContext(ctx)
	repoRoot := r.effectiveRepoRoot(rootDir)
	if repoRoot == "" {
		repoRoot = rootDir
	}
	repoAbs, err := filepath.Abs(repoRoot)
	if err != nil {
		return model.ResolvedFiles{}, err
	}
	rootAbs, err := filepath.Abs(rootDir)
	if err != nil {
		return model.ResolvedFiles{}, err
	}
	if !isUnderRoot(rootAbs, repoAbs) {
		return model.ResolvedFiles{
			Diagnostics: []model.ResolverDiagnostic{{
				FilePath: rootDir,
				Message:  "kustomization root is outside configured repo root",
				QueryID:  "kustomize-render-failed",
				Line:     1,
			}},
		}, nil
	}

	sb, err := sandbox.New()
	if err != nil {
		return model.ResolvedFiles{}, err
	}
	defer func() { _ = sb.Close() }()

	kf := kustomizationEntryFile(rootAbs)
	kustPath := filepath.Join(rootAbs, kf)
	excluded, _ := TransitiveLocalPaths(rootAbs)
	var diags []model.ResolverDiagnostic
	remoteDiags, earlyRemote, stopRemote := remotePolicyResult(rootAbs, kustPath, excluded)
	diags = append(diags, remoteDiags...)
	if stopRemote {
		return earlyRemote, nil
	}

	br, fsRoot, d, err := PrepareHelmChartsIfNeeded(
		ctx, repoAbs, rootAbs, sb.ScratchDir,
		r.opts.AllowHelmInflation, r.opts.HelmIncludeCRDs, r.opts.MaxFetchBytes,
	)
	if errors.Is(err, ErrMaxStagingBytes) {
		return resolvedFilesWithDiagnostics(excluded, append(diags, d...)...), nil
	}
	if err != nil {
		contextLogger.Warn().Msgf("kustomize helm prepass: %v", err)
	}
	buildRoot := br
	runFSRoot := fsRoot
	diags = append(diags, d...)

	scratchAbs := filepath.Clean(sb.ScratchDir)
	brMeta, fsMeta, diags, earlyMeta, stopMeta := maybeStageBuildMetadata(
		ctx, repoAbs, rootDir, scratchAbs, excluded, buildRoot, runFSRoot, diags,
	)
	if stopMeta {
		return earlyMeta, nil
	}
	buildRoot, runFSRoot = brMeta, fsMeta

	runCtx, cancel := context.WithTimeout(ctx, r.opts.RenderTimeout)
	defer cancel()

	yamlOut, err := renderWithTimeout(runCtx, buildRoot, runFSRoot, r.opts.StrictLoad)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return resolvedFilesWithDiagnostics(excluded, append(diags, model.ResolverDiagnostic{
				FilePath: rootDir,
				Message:  "kustomize render timed out",
				QueryID:  "kustomize-render-failed",
				Line:     1,
			})...), nil
		}
		return resolvedFilesWithDiagnostics(excluded, append(diags, model.ResolverDiagnostic{
			FilePath: rootDir,
			Message:  err.Error(),
			QueryID:  "kustomize-render-failed",
			Line:     1,
		})...), nil
	}

	rm, err := parseRenderedResMap(yamlOut)
	if err != nil {
		return resolvedFilesWithDiagnostics(excluded, append(diags, model.ResolverDiagnostic{
			FilePath: rootDir,
			Message:  err.Error(),
			QueryID:  "kustomize-render-failed",
			Line:     1,
		})...), nil
	}

	if rf, stop := rejectIfScratchExceedsLimit(r.opts.MaxFetchBytes, sb.ScratchDir, rootDir, excluded, diags); stop {
		return rf, nil
	}

	out := resolvedVirtualsFromResMap(rm, rootAbs, diags, excluded)
	return out, nil
}

func (r *Resolver) repoRootLimit(rootAbs string) string {
	limit := ""
	if r.opts.RepoRoot != "" {
		if abs, err := filepath.Abs(r.opts.RepoRoot); err == nil {
			limit = filepath.Clean(abs)
		} else {
			limit = filepath.Clean(r.opts.RepoRoot)
		}
	}
	if gitRoot := nearestGitRoot(rootAbs); gitRoot != "" {
		if limit == "" || isUnderRoot(gitRoot, limit) {
			limit = gitRoot
		}
	}
	return limit
}

func (r *Resolver) effectiveRepoRoot(rootDir string) string {
	rootAbs, err := filepath.Abs(rootDir)
	if err != nil {
		rootAbs = filepath.Clean(rootDir)
	}
	limit := r.repoRootLimit(rootAbs)
	cur := rootAbs
	best := rootAbs
	for {
		rels, err := TransitiveRelativeLocalPaths(cur)
		if err != nil || len(rels) == 0 {
			break
		}
		candidate := commonAncestorPathForRoots(rels)
		if candidate == "" || filepath.Clean(candidate) == filepath.Clean(best) {
			break
		}
		if limit != "" && !isUnderRoot(candidate, limit) {
			break
		}
		best = candidate
		cur = candidate
	}
	if limit != "" && isUnderRoot(best, limit) {
		return best
	}
	if limit != "" {
		return limit
	}
	return best
}

func sourcePathForOutput(origin *model.KustomizeOrigin, kustomRoot string, res *resource.Resource) string {
	if origin != nil && origin.SourceFile != "" && filepath.IsAbs(origin.SourceFile) {
		return origin.SourceFile
	}
	if origin != nil && origin.SourceFile != "" && origin.SourceRepo != "" {
		return origin.SourceFile
	}
	if origin != nil && origin.SourceFile != "" {
		return filepath.Clean(filepath.Join(kustomRoot, origin.SourceFile))
	}
	return filepath.Join(kustomRoot, "generated-"+res.GetGvk().Kind+"-"+res.GetName()+".yaml")
}

func metadataPathForResolvedResource(origin *model.KustomizeOrigin, fallback string) string {
	if origin == nil {
		return fallback
	}
	if origin.OriginKind == model.KustomizeOriginTransformer {
		for i := len(origin.Transformations) - 1; i >= 0; i-- {
			if path := origin.Transformations[i].TransformerPath; path != "" && !looksLikeRemotePath(path) {
				return cleanLocalPath(path)
			}
		}
	}
	return fallback
}

// renderWithTimeout runs kustomize in a subprocess so CommandContext can kill
// it on deadline. Prod: same binary as `internal kustomize-render`; tests: same
// test binary with helperEnvVar + MaybeRunAsKustomizeRenderHelper. JSON over stdin/stdout.
func renderWithTimeout(ctx context.Context, buildRoot, runFSRoot string, strictLoad bool) (string, error) {
	argv, extraEnv := helperInvocation()
	bin, binErr := os.Executable()
	if binErr != nil {
		return "", fmt.Errorf("kustomize render helper binary: %w", binErr)
	}
	var cmd *exec.Cmd
	if len(argv) == 0 {
		//nolint:gosec // G204: bin is this process's own executable (os.Executable); no user input.
		cmd = exec.CommandContext(ctx, bin)
	} else {
		//nolint:gosec // G204: bin is os.Executable(); argv is allowlisted in helperInvocation.
		cmd = exec.CommandContext(ctx, bin, argv...)
	}
	cmd.Env = append(os.Environ(), extraEnv...)

	reqBytes, err := json.Marshal(helperRequest{
		BuildRoot:  buildRoot,
		RunFSRoot:  runFSRoot,
		StrictLoad: strictLoad,
	})
	if err != nil {
		return "", fmt.Errorf("encode kustomize render request: %w", err)
	}
	cmd.Stdin = bytes.NewReader(reqBytes)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return "", fmt.Errorf("kustomize render helper: %s", msg)
		}
		return "", fmt.Errorf("kustomize render helper: %w", err)
	}

	var result buildResult
	if err := json.Unmarshal(bytes.TrimSpace(out), &result); err != nil {
		return "", fmt.Errorf("decode kustomize render result: %w", err)
	}
	if result.Err != "" {
		return "", errors.New(result.Err)
	}
	return result.YAML, nil
}

// helperInvocation: prod uses `internal kustomize-render`; tests set helperEnvVar only (main calls MaybeRunAsKustomizeRenderHelper).
func helperInvocation() (argv, env []string) {
	if isTestBinary() {
		return nil, []string{helperEnvVar + "=1"}
	}
	return []string{"internal", "kustomize-render"}, nil
}

func isTestBinary() bool {
	base := filepath.Base(os.Args[0])
	return strings.HasSuffix(base, ".test") || strings.HasSuffix(base, ".test.exe")
}

func parseRenderedResMap(yamlOut string) (resmap.ResMap, error) {
	return resmap.NewFactory(provider.NewDepProvider().GetResourceFactory()).NewResMapFromBytes([]byte(yamlOut))
}

func skipLocalConfig(res *resource.Resource) bool {
	ann := res.GetAnnotations()
	if ann == nil {
		return false
	}
	return ann["config.kubernetes.io/local-config"] == "true"
}

// isUnderRoot: path is root or strictly under root (repo/scratch). Walk-time nested suppression uses provider.isUnderResolvedRoot instead.
func isUnderRoot(path, root string) bool {
	cp := filepath.Clean(path)
	cr := filepath.Clean(root)
	return cp == cr || (strings.HasPrefix(cp, cr+string(filepath.Separator)))
}

func commonAncestorPathForRoots(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	common := filepath.Clean(paths[0])
	for _, p := range paths[1:] {
		cur := filepath.Clean(p)
		for common != cur && !strings.HasPrefix(cur, common+string(filepath.Separator)) {
			parent := filepath.Dir(common)
			if parent == common {
				return common
			}
			common = parent
		}
	}
	return common
}

func nearestGitRoot(path string) string {
	cur := filepath.Clean(path)
	for {
		if _, err := os.Stat(filepath.Join(cur, ".git")); err == nil {
			return cur
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return ""
		}
		cur = parent
	}
}

func resolvedFilesWithDiagnostics(excluded []string, diags ...model.ResolverDiagnostic) model.ResolvedFiles {
	return model.ResolvedFiles{
		Excluded:    stringSliceUnique(excluded),
		Diagnostics: diags,
	}
}

func stringSliceUnique(in []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func originalDataForResolvedResource(origin *model.KustomizeOrigin, renderedYAML string) []byte {
	if origin == nil {
		return []byte(renderedYAML)
	}
	if origin.SourceFile != "" && origin.SourceRepo == "" && filepath.IsAbs(origin.SourceFile) {
		if raw, err := os.ReadFile(origin.SourceFile); err == nil {
			return raw
		}
	}
	if origin.OriginalSourceFile != "" && origin.OriginalSourceRepo == "" && filepath.IsAbs(origin.OriginalSourceFile) {
		if raw, err := os.ReadFile(origin.OriginalSourceFile); err == nil {
			return raw
		}
	}
	return []byte(renderedYAML)
}
