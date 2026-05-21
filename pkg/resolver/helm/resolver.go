package helm

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	masterUtils "github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/pkg/errors"
)

// Resolver is an instance of the helm preprocessor.
type Resolver struct {
	IncludeCRDs bool
}

// NewResolver returns a Helm preprocessor with CRDs included in rendered output (recommended default).
func NewResolver() *Resolver {
	return &Resolver{IncludeCRDs: true}
}

// NewResolverWithIncludeCRDs returns a Helm preprocessor with explicit IncludeCRDs behavior.
func NewResolverWithIncludeCRDs(includeCRDs bool) *Resolver {
	return &Resolver{IncludeCRDs: includeCRDs}
}

// Name implements resolver.Preprocessor.
func (r *Resolver) Name() string {
	return "helm"
}

// Detect returns (KindHELM, true) when path is a chart directory.
func (r *Resolver) Detect(path string) (model.FileKind, bool) {
	_, err := os.Stat(filepath.Join(path, "Chart.yaml"))
	if err != nil {
		return model.KindCOMMON, false
	}
	return model.KindHELM, true
}

// Resolve renders the passed helm chart and returns manifests ready for parsing.
func (r *Resolver) Resolve(ctx context.Context, filePath string) (model.ResolvedFiles, error) {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Msg("Resolving Helm files")
	defer func() {
		if rec := recover(); rec != nil {
			errMessage := "Recovered from panic during resolve of file " + filePath
			masterUtils.HandlePanic(ctx, rec, errMessage)
		}
	}()

	rc, err := RenderChart(ctx, &RenderOptions{
		ChartPath:   filePath,
		IncludeCRDs: r.IncludeCRDs,
	})
	if err != nil {
		return model.ResolvedFiles{}, errors.Wrap(err, "failed to render helm chart")
	}

	var rfiles = model.ResolvedFiles{
		Excluded: rc.Excluded,
	}
	contextLogger.Debug().Msgf("Processing %d helm manifest splits from chart '%s'", len(rc.Resources), filePath)
	for _, res := range rc.Resources {
		subFolder := filepath.Base(filePath)
		splitPath := strings.Split(res.SourceFile, getPathSeparator(res.SourceFile))
		splited := filepath.Join(splitPath[1:]...)
		origpath := filepath.Join(filepath.Dir(filePath), subFolder, splited)
		rfiles.File = append(rfiles.File, model.ResolvedVirtual{
			FileName:     origpath,
			Content:      res.Content,
			OriginalData: res.Original,
			SplitID:      res.SplitID,
			IDInfo:       res.IDInfo,
		})
	}
	contextLogger.Debug().Msgf("Successfully processed %d helm files from chart '%s'", len(rc.Resources), filePath)
	return rfiles, nil
}

// SupportedTypes returns the supported file kinds for this preprocessor.
func (r *Resolver) SupportedTypes() []model.FileKind {
	return []model.FileKind{model.KindHELM}
}

func getPathSeparator(path string) string {
	if strings.Contains(path, "\\") {
		return "\\"
	}
	return "/"
}
