package test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/assets"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/kics"
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
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

const (
	scanID            = "test_scan"
	BaseTestsScanPath = "../assets/queries/"
)


func getFilesMetadatasWithContent(t testing.TB, filePath, platform string, content []byte) model.FileMetadatas {
	combinedParser := getCombinedParser()
	files := make(model.FileMetadatas, 0)

	ctx := context.Background()
	for _, parser := range combinedParser {
		docs, _ := parser.Parse(ctx, filePath, content, true, false, 15)
		if !parser.Parsers.SupportedTypes()[normalizePlatform(platform)] {
			continue
		}
		for _, document := range docs.Docs {
			files = append(files, &model.FileMetadata{
				ID:                uuid.NewString(),
				ScanID:            scanID,
				Document:          kics.PrepareScanDocument(ctx, document, docs.Kind),
				LineInfoDocument:  document,
				OriginalData:      docs.Content,
				Kind:              docs.Kind,
				FilePath:          filePath,
				LinesOriginalData: utils.SplitLines(docs.Content),
				ResolvedFiles:     docs.ResolvedFiles,
			})
		}
	}
	return files
}

func normalizePlatform(platform string) string {
	if platform == "k8s" {
		return "kubernetes"
	}
	return strings.ToLower(platform)
}

func getCombinedParser() []*parser.Parser {
	ctx := context.Background()
	bd, _ := parser.NewBuilder(ctx).
		Add(&jsonParser.Parser{}).
		Add(&yamlParser.Parser{}).
		Add(&bicepParser.Parser{}).
		Add(&cicdParser.Parser{}).
		Add(terraformParser.NewDefault()).
		Add(&protoParser.Parser{}).
		Add(&buildahParser.Parser{}).
		Add(&dockerParser.Parser{}).
		Add(&ansibleConfigParser.Parser{}).
		Add(&ansibleHostsParser.Parser{}).
		Build([]string{""}, []string{""})
	return bd
}

func getQueryContent(queryDir string) (string, error) {
	fullQueryPath := filepath.Join(queryDir, source.QueryFileName)
	content, err := getFileContent(fullQueryPath)
	return string(content), err
}

func getSampleContent(tb testing.TB, params *testCaseParamsType) ([]byte, error) {
	samplePath := checkSampleExistsAndGetPath(tb, params)
	return getFileContent(samplePath)
}

func getFileContent(filePath string) ([]byte, error) {
	return os.ReadFile(filePath)
}

func getSamplePath(tb testing.TB, params *testCaseParamsType) string {
	var samplePath string
	if params.samplePath != "" {
		samplePath = params.samplePath
	} else {
		samplePath = checkSampleExistsAndGetPath(tb, params)
	}
	return samplePath
}

func checkSampleExistsAndGetPath(tb testing.TB, params *testCaseParamsType) string {
	var samplePath string
	var globMatch string
	extensions := fileExtension[params.platform]
	for _, v := range extensions {
		joinedPathList, _ := filepath.Glob(filepath.Join(params.queryDir, fmt.Sprintf("test/positive*%s", v)))
		for _, path := range joinedPathList {
			globMatch = path
			_, err := os.Stat(path)
			if err == nil {
				samplePath = path
				break
			}
		}
	}
	require.False(tb, samplePath == "", "Sample not found in path: %s", globMatch)
	return samplePath
}

func sliceContains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}

func readLibrary(platform string) (source.RegoLibraries, error) {
	ctx := context.Background()
	library := source.GetPathToCustomLibrary(ctx, platform, "./assets/libraries")

	libraryData, err := assets.GetEmbeddedLibraryData(strings.ToLower(platform))
	if err != nil {
		log.Debug().Msgf("Couldn't load input data for library of %s platform.", platform)
		libraryData = "{}"
	}

	if library != "default" {
		content, err := os.ReadFile(library)
		return source.RegoLibraries{
			LibraryCode:      string(content),
			LibraryInputData: libraryData,
		}, err
	}

	log.Debug().Msgf("Custom library not provided. Loading embedded library instead")

	embeddedLibrary, errGettingEmbeddedLibrary := assets.GetEmbeddedLibrary(strings.ToLower(platform))

	return source.RegoLibraries{
		LibraryCode:      embeddedLibrary,
		LibraryInputData: libraryData,
	}, errGettingEmbeddedLibrary
}

func getQueryFilter() *source.QueryInspectorParameters {
	return &source.QueryInspectorParameters{}
}
