/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
)

// findingRouting is what turns the findings a rule raises on the scanned
// documents into the findings of the scan: the callers a deduplicated module
// document stands for, the calls reaching an external module file, and the
// caller files whose filters apply to module findings.
type findingRouting struct {
	extras      map[string][]extraCallerInfo
	moduleFiles map[string]*moduleFileCalls
	callers     map[string]*model.FileMetadata
}

// newFindingRouting indexes the caller files once for the whole scan.
func newFindingRouting(
	extras map[string][]extraCallerInfo, moduleFiles map[string]*moduleFileCalls,
	files model.FileMetadatas, repoPath string,
) *findingRouting {
	callers := make(map[string]*model.FileMetadata)
	for _, f := range files {
		if f == nil || f.ModuleCallChain != "" {
			continue
		}
		key := repoRelativeFile(f.FilePath, repoPath)
		if _, ok := callers[key]; !ok {
			callers[key] = f
		}
	}
	return &findingRouting{extras: extras, moduleFiles: moduleFiles, callers: callers}
}

// findingSink collects the findings of one rule as they are decoded, routed
// and reduced to one per identity.
//
// The scan reports the last finding of each identity (see
// model.FindingIdentity), and a module instantiated per count or for_each
// instance raises the same finding once per instance: one rule can raise
// hundreds of thousands of findings that the report then collapses to a few
// thousand. Holding each identity's latest finding instead gives the report
// the same findings without holding the others until the end of the scan.
type findingSink struct {
	ctx     context.Context
	c       *Inspector
	routing *findingRouting
	out     []model.Vulnerability
	index   map[string]int
	batch   [1]model.Vulnerability
}

func newFindingSink(ctx context.Context, c *Inspector, routing *findingRouting) *findingSink {
	return &findingSink{ctx: ctx, c: c, routing: routing, index: make(map[string]int)}
}

// add routes v and keeps what it routes to. Findings are routed one by one in
// the order the rule raised them, which is the order routing the whole scan at
// once visits them in, so the latest finding of each identity is the one the
// report would have kept.
func (s *findingSink) add(v *model.Vulnerability) {
	s.batch[0] = *v
	routed := s.batch[:]
	routed = expandModuleFindings(routed, s.routing.extras)
	routed = attributeModuleFileFindings(routed, s.routing.moduleFiles)
	routed = s.c.filterAtCallSites(s.ctx, routed, s.routing.callers)
	for i := range routed {
		key := model.FindingIdentity(&routed[i], utils.ChooseQueryID(routed[i].QueryID, routed[i].LegacyQueryID))
		if at, ok := s.index[key]; ok {
			s.out[at] = routed[i]
			continue
		}
		s.index[key] = len(s.out)
		s.out = append(s.out, routed[i])
	}
	s.batch[0] = model.Vulnerability{}
}
