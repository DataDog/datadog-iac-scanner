/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"fmt"

	"github.com/DataDog/datadog-iac-scanner/pkg/policy"
	"github.com/open-policy-agent/opa/v1/ast"
)

type entityDiscoveryUnit struct {
	unit    entityUnitID
	subject string
}

func entityDiscoveryFocus(term *ast.Term) (entityDiscoveryUnit, error) {
	array, ok := term.Value.(*ast.Array)
	if !ok || array.Len() != 2 {
		return entityDiscoveryUnit{}, fmt.Errorf("invalid private discovery focus")
	}
	id, ok := array.Elem(0).Value.(ast.String)
	if !ok {
		return entityDiscoveryUnit{}, fmt.Errorf("invalid discovery unit")
	}
	subject, ok := array.Elem(1).Value.(ast.String)
	if !ok {
		return entityDiscoveryUnit{}, fmt.Errorf("invalid discovery primary")
	}
	return entityDiscoveryUnit{entityUnitID(id), string(subject)}, nil
}

// No discovery value or dirty mark survives a failed pass. Only after the
// complete query succeeds can unmarked units and unresolved identities commit.
func (p *EntityProgram) discover(
	ctx context.Context, reader policy.Reader, input ast.Value, targets map[entitySelector]*ast.Term,
) ([]*ast.Term, entityUnresolved, bool, error) {
	marked := map[entityDiscoveryUnit]bool{}
	rows, unknown, err := entityNativeAttempt(ctx, p.discovery, reader, input, targets, marked)
	if ctx.Err() != nil {
		return nil, nil, false, ctx.Err()
	}
	if err != nil || unknown {
		return nil, nil, false, nil
	}
	values, err := p.discoveryValues(rows, marked)
	if err != nil {
		return nil, nil, false, err
	}
	unresolved := entityUnresolved{}
	for _, unit := range p.plan.units {
		ids := targets[unit.selector].Value.(*ast.Array)
		for i := 0; i < ids.Len(); i++ {
			id := ids.Elem(i)
			if marked[entityDiscoveryUnit{unit.id, string(id.Value.(ast.String))}] {
				unresolved[unit.id] = append(unresolved[unit.id], id)
			}
		}
	}
	return values, unresolved, true, nil
}

func (p *EntityProgram) discoveryValues(rows []*ast.Term, marked map[entityDiscoveryUnit]bool) ([]*ast.Term, error) {
	values := []*ast.Term{}
	for _, row := range rows {
		unit, value, err := entityDiscoveryRecord(row)
		if err != nil {
			return nil, err
		}
		if _, ok := p.units[unit.unit]; !ok {
			return nil, fmt.Errorf("unknown discovery unit %q", unit.unit)
		}
		if marked[unit] {
			continue
		}
		finding, ok := value.Value.(ast.Object)
		if !ok {
			return nil, fmt.Errorf("discovery finding is outside its primary unit")
		}
		subject := finding.Get(ast.StringTerm("_dd_id"))
		if subject == nil || !subject.Equal(ast.StringTerm(unit.subject)) {
			return nil, fmt.Errorf("discovery finding is outside its primary unit")
		}
		values = append(values, value)
	}
	return values, nil
}

func entityDiscoveryRecord(row *ast.Term) (entityDiscoveryUnit, *ast.Term, error) {
	object, ok := row.Value.(ast.Object)
	if !ok {
		return entityDiscoveryUnit{}, nil, fmt.Errorf("invalid discovery record")
	}
	focus := object.Get(ast.StringTerm("unit"))
	value := object.Get(ast.StringTerm("finding"))
	if focus == nil || value == nil {
		return entityDiscoveryUnit{}, nil, fmt.Errorf("incomplete discovery record")
	}
	unit, err := entityDiscoveryFocus(focus)
	return unit, value, err
}
