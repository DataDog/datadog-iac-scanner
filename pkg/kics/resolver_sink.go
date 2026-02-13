/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package kics

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"sort"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/minified"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/google/uuid"
)

func (s *Service) resolverSink(
	ctx context.Context,
	filename, scanID string,
	openAPIResolveReferences bool,
	maxResolverDepth int) ([]string, error) {
	contextLogger := logger.FromContext(ctx)
	kind := s.Resolver.GetType(filename)
	if kind == model.KindCOMMON {
		return []string{}, nil
	}
	resFiles, err := s.Resolver.Resolve(ctx, filename, kind)
	if err != nil {
		contextLogger.Err(err).Msgf("failed to render file content '%s' with fileType '%s'", filename, kind)
		return []string{}, err
	}

	for _, rfile := range resFiles.File {
		s.Tracker.TrackFileFound(rfile.FileName)

		isMinified := minified.IsMinified(rfile.FileName, rfile.Content)
		documents, err := s.Parser.Parse(ctx, rfile.FileName, rfile.Content, openAPIResolveReferences, isMinified, maxResolverDepth)
		if err != nil {
			if documents.Kind == "break" {
				return []string{}, nil
			}
			contextLogger.Err(err).Msgf("failed to parse file content '%s' with fileType '%s'", rfile.FileName, kind)
			return []string{}, nil
		}

		if kind == model.KindHELM {
			ignoreList, errorIL := s.getOriginalIgnoreLines(ctx,
				rfile.FileName, rfile.OriginalData,
				openAPIResolveReferences, isMinified, maxResolverDepth)
			if errorIL == nil {
				documents.IgnoreLines = ignoreList

				// Need to ignore #KICS_HELM_ID Line
				documents.CountLines = bytes.Count(rfile.OriginalData, []byte{'\n'})
			}
		} else {
			documents.CountLines = bytes.Count(rfile.OriginalData, []byte{'\n'}) + 1
		}

		fileCommands := s.Parser.CommentsCommands(ctx, rfile.FileName, rfile.OriginalData)

		for _, document := range documents.Docs {
			_, err = json.Marshal(document)
			if err != nil {
				continue
			}

			if len(documents.IgnoreLines) > 0 {
				sort.Ints(documents.IgnoreLines)
			}

			file := model.FileMetadata{
				ID:                uuid.New().String(),
				ScanID:            scanID,
				Document:          PrepareScanDocument(ctx, document, kind),
				OriginalData:      string(rfile.OriginalData),
				LineInfoDocument:  document,
				Kind:              kind,
				FilePath:          rfile.FileName,
				Content:           string(rfile.Content),
				HelmID:            rfile.SplitID,
				Commands:          fileCommands,
				IDInfo:            rfile.IDInfo,
				LinesIgnore:       documents.IgnoreLines,
				ResolvedFiles:     documents.ResolvedFiles,
				LinesOriginalData: utils.SplitLines(string(rfile.OriginalData)),
				IsMinified:        documents.IsMinified,
			}
			s.saveToFile(ctx, &file)
		}
		s.Tracker.TrackFileParse(rfile.FileName)
		s.Tracker.TrackFileFoundCountLines(documents.CountLines)
		s.Tracker.TrackFileParseCountLines(documents.CountLines - len(documents.IgnoreLines))
		s.Tracker.TrackFileIgnoreCountLines(len(documents.IgnoreLines))

		if kind == model.KindTerraform {
			resourceCount := GetCountTerraformResources(rfile.Content)
			s.Tracker.TrackFileFoundCountResources(resourceCount)
		}
	}
	return resFiles.Excluded, nil
}

func (s *Service) getOriginalIgnoreLines(ctx context.Context, filename string,
	originalFile []uint8,
	openAPIResolveReferences, isMinified bool,
	maxResolverDepth int) (ignoreLines []int, err error) {
	refactor := regexp.MustCompile(`.*\n?.*KICS_HELM_ID.+\n`).ReplaceAll(originalFile, []uint8{})
	refactor = regexp.MustCompile(`{{-\s*(.*?)\s*}}`).ReplaceAll(refactor, []uint8{})

	documentsOriginal, err := s.Parser.Parse(ctx, filename, refactor, openAPIResolveReferences, isMinified, maxResolverDepth)
	if err == nil {
		ignoreLines = documentsOriginal.IgnoreLines
	}
	return
}
