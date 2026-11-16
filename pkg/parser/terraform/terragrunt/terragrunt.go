/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package terragrunt statically evaluates Terragrunt configurations. Nothing
// is executed and the environment is never read: values only known when
// Terragrunt runs (commands, cloud APIs, secrets, state) are unknown.
package terragrunt

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

const (
	// ConfigFileName is the file that makes a directory a Terragrunt unit.
	ConfigFileName = tfpath.TerragruntConfig
	// StackFileName declares a Terragrunt stack.
	StackFileName = tfpath.TerragruntStack

	// maxReadDepth caps nested read_terragrunt_config calls.
	maxReadDepth = 10
)

// Input is one value a unit passes to its module, with where it is set.
type Input struct {
	Value cty.Value
	Range hcl.Range
}

// Unit is an evaluated terragrunt.hcl, merged with the files it includes.
type Unit struct {
	ConfigFile string
	Dir        string
	// Source is terraform.source, "" when the unit directory is the module.
	Source string
	// SourceKnown is false when terraform.source is set but did not evaluate
	// to a known string.
	SourceKnown bool
	SourceRange hcl.Range
	Inputs      map[string]Input
	InputsRange hcl.Range
	// Skip is true when skip or exclude are known to take the unit out of
	// plan and apply.
	Skip bool
	// Includes lists the files the unit includes.
	Includes []string
}

// Evaluator evaluates Terragrunt configurations under one repository root.
// Files outside the root are never read.
type Evaluator struct {
	fsys     vfs.FS
	repoRoot string
}

// New returns an Evaluator reading through fsys, confined to repoRoot.
func New(fsys vfs.FS, repoRoot string) *Evaluator {
	if fsys == nil {
		fsys = vfs.DiskFS{}
	}
	if abs, err := fsys.Abs(repoRoot); err == nil {
		repoRoot = abs
	}
	return &Evaluator{fsys: fsys, repoRoot: filepath.Clean(repoRoot)}
}

// EvaluateUnit evaluates the unit declared by configFile.
func (e *Evaluator) EvaluateUnit(ctx context.Context, configFile string) (*Unit, error) {
	path, err := e.confine(e.repoRoot, configFile)
	if err != nil {
		return nil, err
	}
	s := &scope{terragruntPath: path, originalPath: path, reading: map[string]bool{}}
	cfg, err := e.evaluateConfig(ctx, path, s, true)
	if err != nil {
		return nil, fmt.Errorf("terragrunt: %s: %w", configFile, err)
	}
	unit := &Unit{
		ConfigFile:  path,
		Dir:         filepath.Dir(path),
		Inputs:      cfg.inputs,
		InputsRange: cfg.inputsRange,
		Skip:        cfg.skipped(),
		Includes:    cfg.included,
	}
	if cfg.source != nil {
		unit.SourceRange = cfg.source.Range
		if s, ok := knownString(cfg.source.Value); ok {
			unit.Source, unit.SourceKnown = s, true
		}
	} else {
		unit.SourceKnown = true
	}
	if unit.Inputs == nil {
		unit.Inputs = map[string]Input{}
	}
	return unit, nil
}

func knownString(v cty.Value) (string, bool) {
	if v == cty.NilVal || !v.IsWhollyKnown() || v.IsNull() || v.Type() != cty.String {
		return "", false
	}
	return v.AsString(), true
}
