/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/DataDog/datadog-iac-scanner/pkg/policy"
	"github.com/zclconf/go-cty/cty"
)

// ReadValue reads an evaluated Terraform value before its legacy text rendering.
// The caller owns evaluation diagnostics: NilVal is an error, never absence.
// Only scalar observations are supported here. Reading an aggregate wholesale
// needs explicit collection/shape semantics and cannot inspect a partial copy.
func ReadValue(value cty.Value, path policy.Path) (policy.Read, error) {
	maybe := false
	for _, step := range path {
		if value == cty.NilVal {
			return policy.Read{}, fmt.Errorf("terraform read has no evaluated value")
		}
		value, _ = value.Unmark()
		if value.IsNull() {
			return policy.Read{State: policy.Absent}, nil
		}
		if !value.IsKnown() && !value.Range().DefinitelyNotNull() {
			maybe = true
		}
		next, uncertain, absent, err := readValueStep(value, step)
		if err != nil {
			return policy.Read{}, err
		}
		if absent {
			return policy.Read{State: policy.Absent}, nil
		}
		maybe = maybe || uncertain
		value = next
	}
	return scalarPolicyRead(value, maybe)
}

func readValueStep(value cty.Value, step policy.Step) (next cty.Value, uncertain, absent bool, err error) {
	if key, property := step.Property(); property {
		return readValueProperty(value, key)
	}
	index, _ := step.Position()
	if index < 0 {
		return cty.NilVal, false, true, nil
	}
	typ := value.Type()
	switch {
	case typ.IsTupleType():
		if index >= int64(typ.Length()) {
			return cty.NilVal, false, true, nil
		}
		return value.Index(cty.NumberIntVal(index)), false, false, nil
	case typ.IsListType():
		// HasIndex does not use unknown collection length refinements.
		// ReadValue tracks ancestor nullability independently.
		if !value.IsKnown() {
			bounds := value.Range()
			if index >= int64(bounds.LengthUpperBound()) {
				return cty.NilVal, false, true, nil
			}
			if index < int64(bounds.LengthLowerBound()) {
				return cty.UnknownVal(typ.ElementType()), false, false, nil
			}
		}
		return readValueIndex(value, cty.NumberIntVal(index))
	case typ.IsSetType():
		return cty.NilVal, false, false, &policy.Unsupported{Operation: "indexing a Terraform set"}
	case typ.Equals(cty.DynamicPseudoType):
		return cty.DynamicVal, true, false, nil
	default:
		return cty.NilVal, false, true, nil
	}
}
func readValueProperty(value cty.Value, key string) (next cty.Value, uncertain, absent bool, err error) {
	typ := value.Type()
	switch {
	case typ.IsObjectType():
		if !typ.HasAttribute(key) {
			return cty.NilVal, false, true, nil
		}
		return value.GetAttr(key), false, false, nil
	case typ.IsMapType():
		return readValueIndex(value, cty.StringVal(key))
	case typ.Equals(cty.DynamicPseudoType):
		return cty.DynamicVal, true, false, nil
	default:
		return cty.NilVal, false, true, nil
	}
}
func readValueIndex(value, key cty.Value) (next cty.Value, uncertain, absent bool, err error) {
	if !value.IsKnown() && value.Range().LengthUpperBound() == 0 {
		return cty.NilVal, false, true, nil
	}
	exists := value.HasIndex(key)
	if !exists.IsKnown() {
		return cty.UnknownVal(value.Type().ElementType()), true, false, nil
	}
	if !exists.True() {
		return cty.NilVal, false, true, nil
	}
	return value.Index(key), false, false, nil
}
func scalarPolicyRead(value cty.Value, maybe bool) (policy.Read, error) {
	if value == cty.NilVal {
		return policy.Read{}, fmt.Errorf("terraform read has no evaluated value")
	}
	value, _ = value.Unmark()
	if !value.IsKnown() {
		if !value.Type().IsPrimitiveType() && !value.Type().Equals(cty.DynamicPseudoType) {
			return policy.Read{}, &policy.Unsupported{Operation: "observing a whole unknown Terraform collection or object"}
		}
		return policy.Read{State: policy.Unknown, MaybeAbsent: maybe, NonNull: value.Range().DefinitelyNotNull()}, nil
	}
	if value.IsNull() {
		return policy.Read{State: policy.Null, MaybeAbsent: maybe}, nil
	}
	var scalar any
	switch value.Type() {
	case cty.Bool:
		scalar = value.True()
	case cty.String:
		scalar = value.AsString()
	case cty.Number:
		number := value.AsBigFloat()
		if number.IsInf() {
			return policy.Read{}, &policy.Unsupported{Operation: "observing a non-finite Terraform number"}
		}
		scalar = json.Number(number.Text('f', -1))
	default:
		return policy.Read{}, &policy.Unsupported{Operation: "observing a whole Terraform collection or object"}
	}
	return policy.Read{State: policy.Known, Value: scalar, MaybeAbsent: maybe, NonNull: true}, nil
}

// ValueSubject is a native value in one evaluation unit. Err preserves a
// producer's evaluation failure; callers must not replace failed evaluation
// with a successful unknown value. Values are immutable cty values.
type ValueSubject struct {
	Kind, Type string
	Value      cty.Value
	Err        error
}

// ValueReader exposes native scalar reads for one evaluation unit. Independent
// Terraform roots must use independent readers; this API never infers that
// configurations coexist merely because their resources have matching names.
type ValueReader struct {
	subjects map[string]ValueSubject
	complete bool
	indexes  map[[2]string][]string
}

// NewValueReader snapshots the subject registry, sharing immutable cty values.
// A caller may assert completeness only for an authoritative native inventory.
// Registered subjects must have certain presence. Completeness describes whether
// additional matching subjects may exist; it is never inferred from the registry.
func NewValueReader(subjects map[string]ValueSubject, complete bool) *ValueReader {
	reader := &ValueReader{subjects: make(map[string]ValueSubject, len(subjects)), complete: complete, indexes: map[[2]string][]string{}}
	for id, subject := range subjects {
		reader.subjects[id] = subject
		key := [2]string{subject.Kind, subject.Type}
		reader.indexes[key] = append(reader.indexes[key], id)
	}
	for _, ids := range reader.indexes {
		slices.Sort(ids)
	}
	return reader
}
func (r *ValueReader) CheckSubject(id string) error {
	if _, ok := r.subjects[id]; !ok {
		return fmt.Errorf("unregistered Terraform policy subject %q", id)
	}
	return nil
}
func (r *ValueReader) Inventory(kind, typ string) (policy.Inventory, error) {
	return policy.Inventory{CertainSubjects: slices.Clone(r.indexes[[2]string{kind, typ}]), Complete: r.complete}, nil
}

func (r *ValueReader) Read(id string, path policy.Path) (policy.Read, error) {
	subject, ok := r.subjects[id]
	if !ok {
		return policy.Read{}, fmt.Errorf("unregistered Terraform policy subject %q", id)
	}
	if subject.Err != nil {
		return policy.Read{}, subject.Err
	}
	return ReadValue(subject.Value, path)
}
