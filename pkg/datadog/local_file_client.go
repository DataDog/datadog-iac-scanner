/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package datadog

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
)

// LocalFileClient is a Client backed by a ruleset and library set previously
// fetched from the backend and serialized to local JSON files (see the
// `fetch-bundle` CLI command). It makes no network calls, so it is safe to use
// in network-isolated environments. GetRemoteConfig echoes the local config
// back unchanged: any server-side merge is expected to have already happened
// when the bundle was fetched.
type LocalFileClient struct {
	ruleset   *Ruleset
	libraries map[string]Library
}

var _ Client = (*LocalFileClient)(nil)

// NewLocalFileClient loads a Ruleset and a Library map from rulesetPath and
// librariesPath, both previously written by the `fetch-bundle` CLI command.
func NewLocalFileClient(rulesetPath, librariesPath string) (Client, error) {
	ruleset, err := readJSONFile[Ruleset](rulesetPath)
	if err != nil {
		return nil, fmt.Errorf("could not read local ruleset bundle %q: %w", rulesetPath, err)
	}
	libraries, err := readJSONFile[map[string]Library](librariesPath)
	if err != nil {
		return nil, fmt.Errorf("could not read local libraries bundle %q: %w", librariesPath, err)
	}
	return &LocalFileClient{ruleset: ruleset, libraries: *libraries}, nil
}

func readJSONFile[T any](path string) (*T, error) {
	b, err := os.ReadFile(path) // nolint:gosec
	if err != nil {
		return nil, err
	}
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *LocalFileClient) GetDefaultRuleset(_ context.Context) (*Ruleset, error) {
	return c.ruleset, nil
}

func (c *LocalFileClient) GetDefaultRulesetWithTests(_ context.Context) (*Ruleset, error) {
	return c.ruleset, nil
}

func (c *LocalFileClient) GetCustomRuleset(_ context.Context) (*Ruleset, error) {
	return &Ruleset{ID: CustomRulesetName, Name: CustomRulesetName}, nil
}

func (c *LocalFileClient) GetCustomRulesetWithTests(_ context.Context) (*Ruleset, error) {
	return &Ruleset{ID: CustomRulesetName, Name: CustomRulesetName}, nil
}

// GetRemoteConfig returns localConfig unchanged. The bundle's config.yaml
// (written by `fetch-bundle`) already carries the fully-merged result, so
// callers using LocalFileClient are expected to load that file directly with
// config.ParseConfig rather than routing it back through GetRemoteConfig.
func (c *LocalFileClient) GetRemoteConfig(_ context.Context, _ string, localConfig []byte) ([]byte, error) {
	return localConfig, nil
}

func (c *LocalFileClient) GetLibraries(_ context.Context) (map[string]Library, error) {
	return c.libraries, nil
}
