/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import "sort"

// Reasons a module evaluation is incomplete. Each means some instance the
// configuration declares has no instantiated document, and is scanned only as
// written, if at all.
const (
	// ReasonCanceled is a scan whose context ended during evaluation.
	ReasonCanceled = "canceled"
	// ReasonInstanceLimit is a scan that declares more instances than the
	// configured operational limit.
	ReasonInstanceLimit = "instance_limit"
	// ReasonMemoryLimit is a scan whose evaluation reached the memory boundary.
	ReasonMemoryLimit = "memory_limit"
	// ReasonModuleCycle is a module that calls itself, directly or not, which
	// Terraform rejects.
	ReasonModuleCycle = "module_cycle"
	// ReasonInvalidExpansion is a count or for_each Terraform rejects.
	ReasonInvalidExpansion = "invalid_expansion"
	// ReasonModuleUnresolved is a module call whose source has no directory to
	// evaluate: a missing local path or a remote module not fetched.
	ReasonModuleUnresolved = "module_unresolved"
	// ReasonModuleFailed is a module directory that could not be parsed.
	ReasonModuleFailed = "module_failed"
)

// maxReportExamples bounds the examples a report keeps per reason. It bounds
// the report only; every occurrence is still counted.
const maxReportExamples = 10

// Incompleteness is every occurrence of one reason.
type Incompleteness struct {
	Reason   string   `json:"reason"`
	Count    int      `json:"count"`
	Examples []string `json:"examples,omitempty"`
}

// Report is what one or more evaluations evaluated, and what they could not.
type Report struct {
	// ModuleEvaluations counts module evaluations computed rather than reused,
	// speculative sibling evaluations included.
	ModuleEvaluations int `json:"module_evaluations"`
	// InstanceEvaluations counts resource and data instance bodies evaluated,
	// root module included; a block evaluated again for references between
	// resources counts again.
	InstanceEvaluations int `json:"instance_evaluations"`
	// UnknownExpansions counts count and for_each arguments that depend on
	// values only known at apply time; each is evaluated as one instance with
	// an unknown iteration, as Terraform plans it.
	UnknownExpansions int `json:"unknown_expansions"`
	// CacheHits counts module evaluations reused from the evaluation cache,
	// and CacheEntries the evaluations stored in it.
	CacheHits    int `json:"cache_hits"`
	CacheEntries int `json:"cache_entries"`

	incomplete map[string]*Incompleteness
}

func (r *Report) note(reason, example string) {
	if r.incomplete == nil {
		r.incomplete = make(map[string]*Incompleteness)
	}
	inc, ok := r.incomplete[reason]
	if !ok {
		inc = &Incompleteness{Reason: reason}
		r.incomplete[reason] = inc
	}
	inc.Count++
	if len(inc.Examples) < maxReportExamples && example != "" {
		inc.Examples = append(inc.Examples, example)
	}
}

// Complete reports whether nothing was left unevaluated.
func (r *Report) Complete() bool { return len(r.incomplete) == 0 }

// Incomplete returns every reason recorded, sorted.
func (r *Report) Incomplete() []Incompleteness {
	out := make([]Incompleteness, 0, len(r.incomplete))
	for _, inc := range r.incomplete {
		out = append(out, *inc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Reason < out[j].Reason })
	return out
}

// Merge adds other into r.
func (r *Report) Merge(other *Report) {
	r.ModuleEvaluations += other.ModuleEvaluations
	r.InstanceEvaluations += other.InstanceEvaluations
	r.UnknownExpansions += other.UnknownExpansions
	r.CacheHits += other.CacheHits
	r.CacheEntries += other.CacheEntries
	for reason, inc := range other.incomplete {
		if r.incomplete == nil {
			r.incomplete = make(map[string]*Incompleteness)
		}
		mine, ok := r.incomplete[reason]
		if !ok {
			mine = &Incompleteness{Reason: reason}
			r.incomplete[reason] = mine
		}
		mine.Count += inc.Count
		for _, example := range inc.Examples {
			if len(mine.Examples) < maxReportExamples {
				mine.Examples = append(mine.Examples, example)
			}
		}
	}
}

// Note records an incompleteness found outside evaluation.
func (r *Report) Note(reason, example string) { r.note(reason, example) }
