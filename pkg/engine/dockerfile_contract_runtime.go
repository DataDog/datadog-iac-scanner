package engine

import (
	"fmt"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// validateDockerContractMetadata runs before both isolated and co-compiled
// queries, so compilation caches cannot bypass compatibility requirements.
func (q *QueryLoader) validateDockerContractMetadata(query *model.QueryMetadata) error {
	if query == nil || !strings.EqualFold(query.Platform, "Dockerfile") {
		return nil
	}
	nativeRule := dockerContractRule(query)
	if nativeRule {
		if err := parseDockerContractVersion(query); err != nil {
			return err
		}
	}
	versionedLibrary, present, err := q.dockerLibraryContractVersion(query.Platform)
	if err != nil {
		return err
	}
	if !present && nativeRule {
		return fmt.Errorf("dockerfile contract rule %q has no platform library", query.Query)
	}

	if !nativeRule {
		if versionedLibrary {
			return fmt.Errorf("dockerfile rule %q uses a versioned platform library and must declare custom.datadog.dockerfile.version",
				dockerContractRuleName(query))
		}
		return nil
	}
	if !versionedLibrary {
		return fmt.Errorf("dockerfile library is missing its contract version declaration")
	}
	return nil
}

// dockerLibraryContractVersion distinguishes a legacy library from a versioned
// one. Every rule loaded with a versioned library must declare its contract.
func (q *QueryLoader) dockerLibraryContractVersion(platform string) (versioned, present bool, err error) {
	for libraryPlatform, library := range q.platformLibraries {
		if !strings.EqualFold(libraryPlatform, platform) {
			continue
		}
		metadata := &model.QueryMetadata{Query: "Dockerfile library", Platform: platform, Content: library.LibraryCode}
		config, configured, err := dockerUnitConfig(metadata)
		if err != nil {
			return false, true, err
		}
		_, hasVersion := config["version"]
		if !configured || !hasVersion {
			return false, true, nil
		}
		return true, true, parseDockerContractVersion(metadata)
	}
	return false, false, nil
}

// requireDockerNativeContract caches the declaration check per rule evaluation.
// All roots of a rule share this state; metadata is never reparsed per finding.
func requireDockerNativeContract(qCtx *QueryContext) error {
	if qCtx.dockerGate == nil {
		qCtx.dockerGate = &dockerGateState{}
	}
	state := qCtx.dockerGate
	if state.contractChecked {
		return state.contractErr
	}
	state.contractChecked = true
	config, configured, err := dockerUnitConfig(&qCtx.Query.Metadata)
	if err != nil {
		state.contractErr = err
	} else if !configured || config["version"] == nil {
		state.contractErr = fmt.Errorf("native Dockerfile findings require an explicit contract version")
	} else {
		state.contractErr = parseDockerContractVersion(&qCtx.Query.Metadata)
	}
	return state.contractErr
}
