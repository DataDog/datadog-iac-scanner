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
	"io"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/provider"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/minified"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	"github.com/DataDog/datadog-iac-scanner/pkg/resolver"

	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/pkg/errors"
)

const (
	mbConst = 1048576
)

// Storage is the interface that wraps following basic methods: SaveFile, SaveVulnerabilities, and GetVulnerabilities
// SaveFile should append metadata to a file
// SaveVulnerabilities should append vulnerabilities list to current storage
// GetVulnerabilities should returns all vulnerabilities associated to a scan ID
type Storage interface {
	SaveFile(ctx context.Context, metadata *model.FileMetadata) error
	SaveVulnerabilities(ctx context.Context, vulnerabilities []model.Vulnerability) error
	GetVulnerabilities(ctx context.Context, scanID string) ([]model.Vulnerability, error)
}

// Tracker is the interface that wraps the basic methods: TrackFileFound and TrackFileParse
// TrackFileFound should increment the number of files to be scanned
// TrackFileParse should increment the number of files parsed successfully to be scanned
// TrackFileFoundCountResources should increment the number of resources to be scanned
type Tracker interface {
	TrackFileFound(path string)
	TrackFileParse(path string)
	TrackFileFoundCountLines(countLines int)
	TrackFileParseCountLines(countLines int)
	TrackFileIgnoreCountLines(countLines int)
	TrackFileFoundCountResources(countResources int)
}

// Service is a struct that contains a SourceProvider to receive sources, a storage to save and retrieve scanning informations
// a parser to parse and provide files in format that KICS understand, a inspector that runs the scanning and a tracker to
// update scanning numbers
type Service struct {
	SourceProvider provider.SourceProvider
	Storage        Storage
	Parser         *parser.Parser
	Inspector      *engine.Inspector
	Tracker        Tracker
	Resolver       *resolver.Resolver
	files          model.FileMetadatas
	MaxFileSize    int
}

// PrepareSources will prepare the sources to be scanned
func (s *Service) PrepareSources(ctx context.Context,
	scanID string,
	openAPIResolveReferences bool,
	maxResolverDepth int,
	wg *sync.WaitGroup, errCh chan<- error) {
	contextLogger := logger.FromContext(ctx)
	defer wg.Done()
	// CxSAST query under review
	data := make([]byte, mbConst)
	contextLogger.Info().Msgf("Getting sources")
	if err := s.SourceProvider.GetSources(
		ctx,
		s.Parser.SupportedExtensions(),
		func(ctx context.Context, filename string, rc io.ReadCloser) error {
			return s.sink(ctx, filename, scanID, rc, data, openAPIResolveReferences, maxResolverDepth)
		},
		func(ctx context.Context, filename string) ([]string, error) { // Sink used for resolver files and templates
			return s.resolverSink(ctx, filename, scanID, openAPIResolveReferences, maxResolverDepth)
		},
	); err != nil {
		select {
		case errCh <- errors.Wrap(err, "failed to read sources"):
		case <-ctx.Done():
			return
		}
	}
}

// StartScan executes scan over the context, using the scanID as reference
func (s *Service) StartScan(
	ctx context.Context,
	scanID string,
	errCh chan<- error,
	wg *sync.WaitGroup) {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Msg("service.StartScan()")
	defer wg.Done()

	vulnerabilities, err := s.Inspector.Inspect(
		ctx,
		scanID,
		s.files,
		s.SourceProvider.GetBasePaths(),
		s.Parser.Platform,
	)
	if err != nil {
		select {
		case errCh <- errors.Wrap(err, "failed to inspect files"):
		case <-ctx.Done():
			return
		}
	}

	err = s.Storage.SaveVulnerabilities(ctx, vulnerabilities)
	if err != nil {
		select {
		case errCh <- errors.Wrap(err, "failed to save vulnerabilities"):
		case <-ctx.Done():
			return
		}
	}
}

// Content keeps the content of the file and the number of lines
type Content struct {
	Content        *[]byte
	CountLines     int
	IsMinified     bool
	CountResources int
}

/*
getContent will read the passed file 1MB at a time
to prevent resource exhaustion and return its content
*/
func getContent(rc io.Reader, data []byte, maxSizeMB int, filename string) (*Content, error) {
	var content []byte
	countLines := 0

	c := &Content{
		Content:    &[]byte{},
		CountLines: 0,
	}

	for {
		if maxSizeMB < 0 {
			return c, errors.New("file size limit exceeded")
		}
		data = data[:cap(data)]
		n, err := rc.Read(data)
		if err != nil {
			if err == io.EOF {
				break
			}
			return c, err
		}
		countLines += bytes.Count(data[:n], []byte{'\n'}) + 1
		content = append(content, data[:n]...)
		maxSizeMB--
	}
	c.Content = &content
	c.CountLines = countLines
	c.CountResources = GetCountTerraformResources(content)

	c.IsMinified = minified.IsMinified(filename, content)
	return c, nil
}

// GetVulnerabilities returns a list of scan detected vulnerabilities
func (s *Service) GetVulnerabilities(ctx context.Context, scanID string) ([]model.Vulnerability, error) {
	return s.Storage.GetVulnerabilities(ctx, scanID)
}

func (s *Service) saveToFile(ctx context.Context, file *model.FileMetadata) {
	err := s.Storage.SaveFile(ctx, file)
	if err == nil {
		s.files = append(s.files, *file)
	}
}

// PrepareScanDocument removes _kics_lines from payload and parses json filters
func PrepareScanDocument(ctx context.Context, body map[string]interface{}, kind model.FileKind) map[string]interface{} {
	contextLogger := logger.FromContext(ctx)
	var bodyMap map[string]interface{}
	j, err := json.Marshal(body)
	if err != nil {
		contextLogger.Error().Msgf("failed to remove kics line information")
		return body
	}
	if err := json.Unmarshal(j, &bodyMap); err != nil {
		contextLogger.Error().Msgf("failed to remove kics line information: '%s'", err)
		return body
	}
	prepareScanDocumentRoot(bodyMap, kind)
	return bodyMap
}

func prepareScanDocumentRoot(body interface{}, kind model.FileKind) {
	switch bodyType := body.(type) {
	case map[string]interface{}:
		prepareScanDocumentValue(bodyType, kind)
	case []interface{}:
		for _, indx := range bodyType {
			prepareScanDocumentRoot(indx, kind)
		}
	}
}

func prepareScanDocumentValue(bodyType map[string]interface{}, kind model.FileKind) {
	delete(bodyType, "_kics_lines")
	for key, v := range bodyType {
		switch value := v.(type) {
		case map[string]interface{}:
			prepareScanDocumentRoot(value, kind)
		case []interface{}:
			for _, indx := range value {
				prepareScanDocumentRoot(indx, kind)
			}
		case string:
			if field, ok := lines[kind]; ok && utils.Contains(key, field) {
				bodyType[key] = resolveJSONFilter(value)
			}
		}
	}
}
