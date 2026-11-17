package engine

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	dockerparser "github.com/DataDog/datadog-iac-scanner/pkg/parser/docker"
	"github.com/open-policy-agent/opa/v1/ast"
)

const dockerContractModuleName = "dockerfile-contract.rego"

// dockerContractModule is an engine-provided capability surface. A rule or
// library that calls it fails to compile on scanner versions that do not
// inject this module, while standalone OPA tests can provide a test-only stub.
const dockerContractModule = `package datadog_scanner

import rego.v1

dockerfile_v1(1) := true
`

// DockerfileContractRego returns the engine-owned module for static tools that
// compile Dockerfile policies. Evaluation must still use Inspector's contract
// and input validation; this module is only the declared capability surface.
func DockerfileContractRego() string { return dockerContractModule }

// parseDockerContractVersion reads the package-level declaration that opts a
// Dockerfile rule into the versioned facts contract. A native contract rule
// without a declaration is an error: silently treating it as a legacy rule
// could produce an empty result on a scanner with a different model.
func parseDockerContractVersion(query *model.QueryMetadata) error {
	if query == nil || !strings.EqualFold(query.Platform, "Dockerfile") {
		return nil
	}
	if legacy, _ := query.Metadata["contract"].(string); legacy == "legacy" && dockerContractRule(query) {
		return fmt.Errorf("dockerfile rule %q cannot use legacy mode with the native contract", dockerContractRuleName(query))
	}

	config, configured, err := dockerUnitConfig(query)
	if err != nil {
		return fmt.Errorf("parse dockerfile rule contract metadata for rule %q: %w", dockerContractRuleName(query), err)
	}
	raw, present := config["version"]
	if !configured || !present {
		if dockerContractRule(query) {
			return fmt.Errorf("dockerfile contract rule %q is missing custom.datadog.dockerfile.version", dockerContractRuleName(query))
		}
		return nil
	}
	version, err := dockerContractVersionValue(raw)
	if err != nil {
		return fmt.Errorf("dockerfile rule %q: %w", dockerContractRuleName(query), err)
	}
	if version != dockerparser.ContractVersion {
		return fmt.Errorf("dockerfile rule %q requires contract version %d; scanner supports version %d",
			dockerContractRuleName(query), version, dockerparser.ContractVersion)
	}
	return nil
}

func dockerContractVersionValue(raw interface{}) (int, error) {
	var text string
	switch value := raw.(type) {
	case int:
		if value < 1 {
			return 0, fmt.Errorf("dockerfile contract version must be a positive integer")
		}
		return value, nil
	case int64:
		if value < 1 {
			return 0, fmt.Errorf("dockerfile contract version must be a positive integer")
		}
		return int(value), nil
	case float64:
		if value < 1 || value != float64(int(value)) {
			return 0, fmt.Errorf("dockerfile contract version must be a positive integer")
		}
		return int(value), nil
	case ast.Number:
		text = value.String()
	default:
		return 0, fmt.Errorf("dockerfile contract version must be a positive integer")
	}
	version, err := strconv.Atoi(text)
	if err != nil || version < 1 {
		return 0, fmt.Errorf("dockerfile contract version must be a positive integer")
	}
	return version, nil
}

func dockerContractRuleName(query *model.QueryMetadata) string {
	if query != nil {
		if id, ok := query.Metadata["id"].(string); ok && id != "" {
			return id
		}
	}
	if query != nil && query.Query != "" {
		return query.Query
	}
	return "<unknown>"
}

// validateDockerContractInput checks the full platform input before selecting any Docker
// instruction units. Missing document arrays represent empty input.
func validateDockerContractInput(input ast.Value, placeholder string) error {
	root, ok := input.(ast.Object)
	if !ok {
		return fmt.Errorf("dockerfile contract input must be an object")
	}
	documentsTerm := root.Get(ast.StringTerm("document"))
	if documentsTerm == nil {
		return nil
	}
	documents, ok := documentsTerm.Value.(*ast.Array)
	if !ok {
		return fmt.Errorf("dockerfile contract input document must be an array")
	}
	for i := 0; i < documents.Len(); i++ {
		if err := validateDockerContractDocument(documents.Elem(i), i, placeholder); err != nil {
			return err
		}
	}
	return nil
}

func validateDockerContractDocument(docTerm *ast.Term, i int, placeholder string) error {
	doc, ok := docTerm.Value.(ast.Object)
	if !ok {
		return fmt.Errorf("dockerfile contract input document %d must be an object", i)
	}
	idTerm := doc.Get(ast.StringTerm("id"))
	if idTerm == nil {
		return fmt.Errorf("dockerfile contract input document %d is missing its identity", i)
	}
	idValue, ok := idTerm.Value.(ast.String)
	if !ok || idValue == "" {
		return fmt.Errorf("dockerfile contract input document %d has an invalid identity", i)
	}
	id := string(idValue)
	modelTerm := doc.Get(ast.StringTerm("_dockerfile"))
	if modelTerm == nil {
		return fmt.Errorf("dockerfile contract input %q is missing its model", id)
	}
	facts, ok := modelTerm.Value.(ast.Object)
	if !ok {
		return fmt.Errorf("dockerfile contract input %q has an invalid model", id)
	}
	versionTerm := facts.Get(ast.StringTerm("contract_version"))
	if versionTerm == nil {
		return fmt.Errorf("dockerfile contract input %q is missing contract_version; scanner supports version %d",
			id, dockerparser.ContractVersion)
	}
	version, ok := versionTerm.Value.(ast.Number)
	if !ok {
		return fmt.Errorf("dockerfile contract input %q has invalid contract_version; scanner supports version %d",
			id, dockerparser.ContractVersion)
	}
	actual, err := strconv.Atoi(version.String())
	if err != nil || actual < 1 {
		return fmt.Errorf("dockerfile contract input %q has invalid contract_version %q; scanner supports version %d",
			id, version, dockerparser.ContractVersion)
	}
	if actual != dockerparser.ContractVersion {
		return fmt.Errorf("dockerfile contract input %q has contract version %d; scanner supports version %d",
			id, actual, dockerparser.ContractVersion)
	}
	if err := validateDockerModelV1(id, facts, placeholder); err != nil {
		return err
	}
	return nil
}

// validateDockerModelV1 checks the required root schema for a full version 1
// model. It deliberately validates only the stable top-level shape; individual
// fact details remain owned by the parser and can evolve with the contract.
func validateDockerModelV1(id string, facts ast.Object, placeholder string) error {
	for _, field := range []string{"instructions", "stages", "stage_names", "contexts", "bindings"} {
		term := facts.Get(ast.StringTerm(field))
		if term == nil {
			return fmt.Errorf("dockerfile contract input %q is missing model field %q", id, field)
		}
		if _, ok := term.Value.(*ast.Array); !ok {
			return fmt.Errorf("dockerfile contract input %q model field %q must be an array", id, field)
		}
	}
	for _, field := range []string{"resource_type", "resource_name"} {
		term := facts.Get(ast.StringTerm(field))
		if term == nil {
			return fmt.Errorf("dockerfile contract input %q is missing model field %q", id, field)
		}
		value, ok := term.Value.(ast.String)
		if !ok || strings.TrimSpace(string(value)) == "" {
			return fmt.Errorf("dockerfile contract input %q model field %q must be a non-empty string", id, field)
		}
	}
	globalArguments := facts.Get(ast.StringTerm("global_arguments"))
	if globalArguments == nil {
		return fmt.Errorf("dockerfile contract input %q is missing model field %q", id, "global_arguments")
	}
	if placeholder != "" {
		if unknown, ok := globalArguments.Value.(ast.String); ok && string(unknown) == placeholder {
			return nil
		}
	}
	globalArgumentIndex, ok := globalArguments.Value.(ast.Number)
	if !ok {
		return fmt.Errorf("dockerfile contract input %q model field %q must be an integer", id, "global_arguments")
	}
	index, err := strconv.Atoi(globalArgumentIndex.String())
	if err != nil || index < 0 {
		return fmt.Errorf("dockerfile contract input %q model field %q must be a non-negative integer", id, "global_arguments")
	}
	return nil
}
