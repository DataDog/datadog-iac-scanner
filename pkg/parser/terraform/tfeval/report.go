/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

// Report counts the work one or more evaluations did.
type Report struct {
	// ModuleEvaluations counts module evaluations computed rather than reused,
	// speculative sibling evaluations included.
	ModuleEvaluations int `json:"module_evaluations"`
	// InstanceEvaluations counts resource and data instance bodies evaluated,
	// root module included; a block evaluated again for references between
	// resources counts again.
	InstanceEvaluations int `json:"instance_evaluations"`
	// CacheHits counts module evaluations reused from the evaluation cache,
	// and CacheEntries the evaluations stored in it.
	CacheHits    int `json:"cache_hits"`
	CacheEntries int `json:"cache_entries"`
}

// Merge adds other into r.
func (r *Report) Merge(other *Report) {
	r.ModuleEvaluations += other.ModuleEvaluations
	r.InstanceEvaluations += other.InstanceEvaluations
	r.CacheHits += other.CacheHits
	r.CacheEntries += other.CacheEntries
}
