/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

type moduleContextKey struct{ dir, root string }

// moduleContext contains only values fixed by the module and root directories.
// The maps are read-only; each evaluation keeps its own variable map.
type moduleContext struct {
	functions map[string]function.Function
	variables map[string]cty.Value
}

func (e *Evaluator) moduleContext(dir, root string) moduleContext {
	key := moduleContextKey{dir: dir, root: root}
	if cached, ok := e.contexts[key]; ok {
		return cached
	}
	shared := moduleContext{
		functions: functions.EvalFuncsWithRoot(dir, root, e.funcFS),
		variables: functions.ContextVariables(dir, root),
	}
	if e.contexts == nil {
		e.contexts = make(map[moduleContextKey]moduleContext)
	}
	e.contexts[key] = shared
	return shared
}
