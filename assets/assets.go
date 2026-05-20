package assets

import (
	"context"
	"embed" // used for embedding KICS libraries
	"fmt"
)

//go:embed libraries/*.rego
var embeddedLibraries embed.FS

//go:embed libraries/*.json
var embeddedLibraryData embed.FS

// GetEmbeddedLibrary returns the embedded library.rego for the platform passed in the argument
func GetEmbeddedLibrary(platform string) (string, error) {
	content, err := embeddedLibraries.ReadFile("libraries/" + platform + ".rego")
	return string(content), err
}

// GetEmbeddedLibraryData returns the embedded library.json for the platform passed in the argument
func GetEmbeddedLibraryData(platform string) (string, error) {
	content, err := embeddedLibraryData.ReadFile("libraries/" + platform + ".json")
	return string(content), err
}

// GetEmbeddedQueriesFs returns an empty FS; assets/queries/ has been removed and rules are now served by the backend.
func GetEmbeddedQueriesFs() embed.FS {
	return embed.FS{}
}

// GetEmbeddedQueryDirs returns nil; assets/queries/ has been removed.
func GetEmbeddedQueryDirs(_ context.Context) ([]string, error) {
	return nil, nil
}

// GetEmbeddedQueryFile returns an error; assets/queries/ has been removed.
func GetEmbeddedQueryFile(_ context.Context, path string) ([]byte, error) {
	return nil, fmt.Errorf("embedded queries removed: %s", path)
}
