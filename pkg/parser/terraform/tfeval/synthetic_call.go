/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// SyntheticCall is a module call that is not written as a module block, such
// as a Terragrunt unit calling its terraform.source.
type SyntheticCall struct {
	// Label names the call; its resources are addressed module.<Label>.
	Label   string
	Source  string
	Version string
	// CallerFile declares the call; relative sources resolve from its directory.
	CallerFile string
	// Range is the call-site anchor in CallerFile.
	Range hcl.Range
	// Body holds one attribute per argument, positioned where the argument is
	// set, so findings can be traced back to it. It may be nil.
	Body *hclsyntax.Body
}

// EvaluateCall evaluates the module call's source with inputs, as if a module
// block in CallerFile called it. The module is its own Terraform root.
// visitedDirs includes the called directory when evaluation succeeds. Any
// failure other than cancellation wraps ErrModuleNotEvaluated.
func (e *Evaluator) EvaluateCall(
	ctx context.Context,
	call *SyntheticCall,
	inputs map[string]cty.Value,
) (resources []ResolvedResource, outputs map[string]cty.Value, visitedDirs map[string]bool, err error) {
	if call == nil || call.Label == "" || call.Source == "" || call.CallerFile == "" {
		return nil, nil, nil, fmt.Errorf("%w: synthetic call needs a label, a source and a caller file", ErrModuleNotEvaluated)
	}
	callerFile, absErr := e.fsys.Abs(call.CallerFile)
	if absErr != nil {
		callerFile = filepath.Clean(call.CallerFile)
	}
	dir, packageRoot, ok := e.resolveModuleDir(
		ctx, filepath.Dir(callerFile), "", call.Source, call.Version, callerFile, call.Label,
	)
	if !ok {
		return nil, nil, nil, fmt.Errorf("%w: source %q of %s did not resolve", ErrModuleNotEvaluated, call.Source, callerFile)
	}

	site := CallSite{
		ModuleName:      call.Label,
		Source:          call.Source,
		Version:         call.Version,
		CalledFrom:      callerFile,
		CalledLine:      call.Range.Start.Line,
		CalledEndLine:   call.Range.End.Line,
		CalledColumn:    call.Range.Start.Column,
		CalledEndColumn: call.Range.End.Column,
		Body:            call.Body,
	}
	addr := joinAddr("", "module."+call.Label)
	chain := []CallSite{site}

	visiting := map[string]bool{}
	allVisited := map[string]bool{}
	e.instances = nil
	resources, outputs, err = e.evaluate(ctx, dir, dir, packageRoot, inputs, addr, chain, 0, visiting, allVisited)
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		e.instances = nil
		if isReportableModuleEvalError(err) {
			contextLogger := logger.FromContext(ctx)
			contextLogger.Warn().Msgf("tfeval: failed to evaluate %s called from %s: %v", dir, callerFile, err)
		}
		if ctx.Err() == nil && !errors.Is(err, ErrModuleNotEvaluated) {
			err = fmt.Errorf("%w: %w", ErrModuleNotEvaluated, err)
		}
		return nil, nil, nil, err
	}
	e.recordModuleInstance(dir, addr, chain)
	allVisited[dir] = true
	return resources, outputs, allVisited, nil
}
