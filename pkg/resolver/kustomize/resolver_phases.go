package kustomize

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/rootfile"
	"gopkg.in/yaml.v3"
	"sigs.k8s.io/kustomize/api/resmap"
)

func rejectIfScratchExceedsLimit(
	maxBytes int64,
	scratchDir string,
	excluded []string,
) (model.ResolvedFiles, bool) {
	if maxBytes <= 0 {
		return model.ResolvedFiles{}, false
	}
	sz, szErr := DirTotalSize(scratchDir)
	if szErr != nil || sz <= maxBytes {
		return model.ResolvedFiles{}, false
	}
	return model.ResolvedFiles{Excluded: stringSliceUnique(excluded)}, true
}

// remotePolicyWalk scans the kustomization tree for remote refs and inline KRM diagnostics.
func remotePolicyWalk(rootAbs string) (
	firstRemotePath string,
	firstRemoteRefs []string,
	krmDiags []ResolverDiagnostic,
	walkErr error,
) {
	walkErr = WalkLocalKustomizations(rootAbs, func(kustPath string, raw []byte) error {
		if rem, err := CollectRemoteRefsFromKustomization(raw); err == nil && len(rem) > 0 && firstRemotePath == "" {
			firstRemotePath = kustPath
			firstRemoteRefs = append([]string(nil), rem...)
		}
		var doc map[string]interface{}
		if err := yaml.Unmarshal(raw, &doc); err == nil && DetectKRMInlineFunctions(doc) {
			krmDiags = append(krmDiags, ResolverDiagnostic{
				FilePath: kustPath,
				Message:  "inline KRM generators/transformers/validators are not executed in this scanner",
				QueryID:  "kustomize-exec-plugin-disabled",
				Line:     1,
			})
		}
		return nil
	})
	return firstRemotePath, firstRemoteRefs, krmDiags, walkErr
}

func remotePolicyResult(rootAbs, kustPath string, excluded []string) ([]ResolverDiagnostic, model.ResolvedFiles, bool) {
	firstRemotePath, firstRemoteRefs, krmDiags, remotePolicyErr := remotePolicyWalk(rootAbs)
	if remotePolicyErr == nil && len(firstRemoteRefs) > 0 {
		return []ResolverDiagnostic{remoteRefWarning(firstRemotePath, firstRemoteRefs)}, model.ResolvedFiles{
			Excluded: stringSliceUnique(append(excluded, firstRemotePath)),
		}, true
	}
	return appendKRMIfWalkFailed(kustPath, remotePolicyErr, krmDiags), model.ResolvedFiles{}, false
}

func appendKRMIfWalkFailed(kustPath string, remotePolicyErr error, diags []ResolverDiagnostic) []ResolverDiagnostic {
	if remotePolicyErr == nil {
		return diags
	}
	if raw, err := rootfile.ReadFile(kustPath); err == nil {
		var doc map[string]interface{}
		if err := yaml.Unmarshal(raw, &doc); err == nil && DetectKRMInlineFunctions(doc) {
			diags = append(diags, ResolverDiagnostic{
				FilePath: kustPath,
				Message:  "inline KRM generators/transformers/validators are not executed in this scanner",
				QueryID:  "kustomize-exec-plugin-disabled",
				Line:     1,
			})
		}
	}
	return diags
}

func logResolverDiagnostics(ctx context.Context, diags []ResolverDiagnostic) {
	if len(diags) == 0 {
		return
	}
	contextLogger := logger.FromContext(ctx)
	for _, d := range diags {
		contextLogger.Warn().Msgf("%s: %s (%s)", d.FilePath, d.Message, d.QueryID)
	}
}

func resolverWarning(filePath, message, queryID string) ResolverDiagnostic {
	return ResolverDiagnostic{
		FilePath: filePath,
		Message:  message,
		QueryID:  queryID,
		Line:     1,
	}
}

func renderFailure(filePath, message string) ResolverDiagnostic {
	return resolverWarning(filePath, message, "kustomize-render-failed")
}

func scratchLimitWarning(rootDir string, sz, maxBytes int64) ResolverDiagnostic {
	return resolverWarning(
		rootDir,
		fmt.Sprintf("kustomize scratch dir size exceeds configured maximum (%d > %d bytes)", sz, maxBytes),
		"kustomize-max-fetch-exceeded",
	)
}

func remoteRefWarning(filePath string, refs []string) ResolverDiagnostic {
	return ResolverDiagnostic{
		FilePath: filePath,
		Message:  fmt.Sprintf("kustomization references remote resources which are not supported: %v", refs),
		QueryID:  "kustomize-remote-disallowed",
		Line:     1,
	}
}

// maybeStageBuildMetadata returns done=true and rf when Resolve should return rf immediately.
func maybeStageBuildMetadata(
	ctx context.Context,
	repoAbs, rootDir, scratchAbs string,
	excluded []string,
	buildRoot, runFSRoot string,
	diags []ResolverDiagnostic,
) (brOut, fsOut string, diagsOut []ResolverDiagnostic, rf model.ResolvedFiles, done bool) {
	contextLogger := logger.FromContext(ctx)
	buildAbs := filepath.Clean(buildRoot)
	kustRel := kustomizationEntryFile(buildAbs)
	metaPath := filepath.Join(buildAbs, kustRel)
	metaBytes, err := rootfile.ReadFile(metaPath)
	if err != nil {
		return buildRoot, runFSRoot, diags, model.ResolvedFiles{}, false
	}
	need, err := buildMetadataSupplementsNeeded(metaBytes)
	if err != nil {
		contextLogger.Warn().Msgf("kustomize buildMetadata read: %v", err)
		return buildRoot, runFSRoot, diags, model.ResolvedFiles{}, false
	}
	if !need {
		return buildRoot, runFSRoot, diags, model.ResolvedFiles{}, false
	}
	if isUnderRoot(buildAbs, scratchAbs) {
		if err := ensureBuildMetadataIfNeeded(buildRoot); err != nil {
			contextLogger.Warn().Msgf("kustomize buildMetadata: %v", err)
		}
		return buildRoot, runFSRoot, diags, model.ResolvedFiles{}, false
	}
	relFromRepo, relErr := filepath.Rel(repoAbs, buildAbs)
	if relErr != nil || relFromRepo == relDotDot || strings.HasPrefix(relFromRepo, parentDirPrefix) {
		return "", "", nil, model.ResolvedFiles{Excluded: stringSliceUnique(excluded)}, true
	}
	sum := sha256.Sum256([]byte(repoAbs + "\x00" + buildAbs))
	stagedRepo := filepath.Join(scratchAbs, "kustomize-build", hex.EncodeToString(sum[:]))
	_ = os.RemoveAll(stagedRepo)
	stageRels, stageErr := BuildMetadataStageRelPaths(repoAbs, buildAbs)
	if stageErr != nil {
		return "", "", nil, model.ResolvedFiles{Excluded: stringSliceUnique(excluded)}, true
	}
	if err := CopyRepoRelativeFilesNoSymlinks(stagedRepo, repoAbs, stageRels); err != nil {
		return "", "", nil, model.ResolvedFiles{Excluded: stringSliceUnique(excluded)}, true
	}
	stagedKustom := filepath.Join(stagedRepo, relFromRepo)
	if err := ensureBuildMetadataIfNeeded(stagedKustom); err != nil {
		contextLogger.Warn().Msgf("kustomize buildMetadata: %v", err)
	}
	return stagedKustom, stagedRepo, diags, model.ResolvedFiles{}, false
}

func appendMissingTransformerPathDiags(
	origin *model.KustomizeOrigin,
	repoAbs, scratchAbs string,
	seen map[string]struct{},
	diags []ResolverDiagnostic,
) []ResolverDiagnostic {
	if origin == nil || len(origin.Transformations) == 0 {
		return diags
	}
	for _, tr := range origin.Transformations {
		if tr.TransformerPath == "" || strings.Contains(tr.TransformerPath, "://") {
			continue
		}
		// Skip paths outside the repo/scratch sandbox so attacker-controlled
		// origin annotations don't probe host files or leak into diagnostics.
		if !isResolvedFileSafe(tr.TransformerPath, repoAbs, scratchAbs) {
			continue
		}
		if _, err := rootfile.Lstat(tr.TransformerPath); err != nil {
			key := origin.GeneratorConfigFile + "\x00" + tr.FieldPath + "\x00" + tr.TransformerPath
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			diags = append(diags, ResolverDiagnostic{
				FilePath: origin.GeneratorConfigFile,
				Message: fmt.Sprintf(
					"transformer patch not found at %q (declared path %q)",
					tr.TransformerPath, tr.FieldPath,
				),
				QueryID: "kustomize-transformer-path-missing",
				Line:    1,
			})
		}
	}
	return diags
}

// isResolvedFileSafe reports whether a kustomize-supplied path may be read as
// scan source bytes. It rejects empty/remote/relative paths and any path that
// is not under one of the configured roots (repo or scratch).
func isResolvedFileSafe(path string, roots ...string) bool {
	if path == "" || strings.Contains(path, "://") || !filepath.IsAbs(path) {
		return false
	}
	clean := filepath.Clean(path)
	for _, r := range roots {
		if r != "" && isUnderRoot(clean, r) {
			return true
		}
	}
	return false
}

// safeReadResolvedFile reads path through rootfile only when it satisfies
// isResolvedFileSafe. Returns ok=false on any rejection or read error.
func safeReadResolvedFile(path string, roots ...string) ([]byte, bool) {
	if !isResolvedFileSafe(path, roots...) {
		return nil, false
	}
	raw, err := rootfile.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, false
	}
	return raw, true
}

func resolvedVirtualsFromResMap(
	rm resmap.ResMap,
	rootAbs, repoAbs, scratchAbs string,
	diags []ResolverDiagnostic,
	excluded []string,
) model.ResolvedFiles {
	var out model.ResolvedFiles
	out.Excluded = stringSliceUnique(excluded)
	missingTransformerDiag := map[string]struct{}{}
	for _, res := range rm.Resources() {
		if skipLocalConfig(res) {
			continue
		}
		yml := res.MustYaml()
		origin := OriginFromResource(res, rootAbs)
		diags = appendMissingTransformerPathDiags(origin, repoAbs, scratchAbs, missingTransformerDiag, diags)
		if origin != nil && origin.SourceFile != "" && origin.SourceRepo == "" && !filepath.IsAbs(origin.SourceFile) {
			origin.SourceFile = filepath.Join(rootAbs, origin.SourceFile)
		}
		srcPath := sourcePathForOutput(origin, rootAbs, res)
		metadataPath := metadataPathForResolvedResource(origin, srcPath)
		orig := originalDataForResolvedResource(origin, yml, repoAbs, scratchAbs)
		if metadataPath != "" {
			if raw, ok := safeReadResolvedFile(metadataPath, repoAbs, scratchAbs); ok {
				orig = raw
			} else if metadataPath != srcPath {
				// Untrusted transformer path: don't surface it to downstream
				// parsers/sinks; fall back to the rendered source path.
				metadataPath = srcPath
			}
		}
		out.File = append(out.File, model.ResolvedVirtual{
			FileName:     srcPath,
			MetadataPath: metadataPath,
			Content:      []byte(yml),
			OriginalData: orig,
			Origin:       origin,
		})
	}
	return out
}
