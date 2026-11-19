/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package policy defines the platform-independent boundary between evaluated
// infrastructure and security policies. Platform adapters own evaluation and
// provenance; opaque subject identities are not reporting fingerprints.
package policy

import (
	"encoding/json"
	"fmt"
)

// Step is a typed property name or sequence index. Its zero value is the empty
// property name; it is not an index. Paths never parse dotted property names.
type Step struct {
	key     string
	index   int64
	indexed bool
}

func Key(key string) Step               { return Step{key: key} }
func Index(index int64) Step            { return Step{index: index, indexed: true} }
func (s Step) Property() (string, bool) { return s.key, !s.indexed }
func (s Step) Position() (int64, bool)  { return s.index, s.indexed }
func (s Step) MarshalJSON() ([]byte, error) {
	if s.indexed {
		return json.Marshal(s.index)
	}
	return json.Marshal(s.key)
}

type Path []Step

// State describes a read's semantic result. Null is a present value; Absent
// means the adapter proved absence. Evaluation failures are returned as errors.
type State uint8

const (
	Invalid State = iota
	Absent
	Null
	Known
	Unknown
)

// Read contains a scalar fact. Known values use string, bool or json.Number;
// null has its own state. Unknown values never use a concrete placeholder.
// MaybeAbsent and NonNull are authoritative refinements, not policy guesses.
// Symbol optionally correlates repeated reads of the same unknown value across
// subject/path aliases; an empty symbol gives that read its own stable identity.
// Value correlation does not establish equal presence for different observations.
type Read struct {
	State       State
	Value       any
	MaybeAbsent bool
	NonNull     bool
	Symbol      string
}

// Reader is immutable for an evaluation and safe for concurrent use. Entities
// must reject inventories whose membership is not authoritative for this API;
// an incomplete inventory cannot silently look empty. Read must reject unknown
// subjects and unsupported operations rather than interpret either as absence.
// Entities returns a caller-owned slice; retaining, reordering or appending to
// it must not mutate the reader. Adapters must not retain or mutate read paths.
type Reader interface {
	CheckSubject(subject string) error
	Entities(kind, typ string) ([]string, error)
	Read(subject string, path Path) (Read, error)
}

// Unsupported describes a semantic operation an adapter cannot establish.
// Callers must surface this diagnostic; it does not mean the policy is clean.
type Unsupported struct{ Operation string }

func (e *Unsupported) Error() string {
	return fmt.Sprintf("unsupported policy operation: %s", e.Operation)
}
