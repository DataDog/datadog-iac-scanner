/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package parser_test

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/analyzer"
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
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
)

func TestAnalyzerFileTypesHaveParsers(t *testing.T) {
	// Register the scan's parsers with all platforms enabled. Every analyzer
	// token needs a consumer or prepare silently drops files of that type.
	parsers, err := parser.NewBuilder(t.Context()).
		Add(&yamlParser.Parser{}).
		Add(dockerComposeParser.NewDefaultWithFS(vfs.DiskFS{})).
		Add(terraformParser.NewDefault()).
		Add(&bicepParser.Parser{}).
		Add(&cicdParser.Parser{}).
		Add(&dockerParser.Parser{}).
		Add(&protoParser.Parser{}).
		Add(&buildahParser.Parser{}).
		Add(&ansibleConfigParser.Parser{}).
		Add(&ansibleHostsParser.Parser{}).
		Add(&jsonParser.Parser{}).
		Build([]string{""}, []string{""})
	require.NoError(t, err)
	claimed := make(map[string]bool)
	for _, p := range parsers {
		for _, extension := range p.Parsers.SupportedExtensions() {
			claimed[extension] = true
		}
	}
	for _, token := range analyzer.PossibleFileTypes() {
		t.Run(token, func(t *testing.T) {
			require.True(t, claimed[token], "analyzer token %q has no registered parser", token)
		})
	}
}
