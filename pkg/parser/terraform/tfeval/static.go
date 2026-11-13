/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

// dirStatic is dependency analysis of parsed syntax, shared by every instance
// of a directory. None of these answers depends on the evaluated input values.
type dirStatic struct {
	siblings           []siblingReads
	resourcesReadOwn   bool
	resourcesReadData  bool
	dataReadsData      bool
	dataReadsLocals    bool
	dataReadsResources bool
	dataReadsModules   bool
}

func newDirStatic(dp *dirParse) *dirStatic {
	s := &dirStatic{
		siblings:         callSiblingReads(dp.modules),
		resourcesReadOwn: dp.locals.readsResources || resourcesReadResources(dp.resources, dp.resourceTypes),
		resourcesReadData: resourcesReadResources(dp.resources, dataRoot) ||
			resourcesReadNamedLocals(dp.resources, dp.locals.dataLocals),
	}
	for _, b := range dp.locals.dataBlocks {
		s.dataReadsData = s.dataReadsData || bodyReadsResource(b.Body, dataRoot)
		s.dataReadsLocals = s.dataReadsLocals || bodyReadsResource(b.Body, localRoot)
		s.dataReadsResources = s.dataReadsResources || bodyReadsResource(b.Body, dp.resourceTypes)
		s.dataReadsModules = s.dataReadsModules || bodyReadsResource(b.Body, moduleRoot)
	}
	s.dataReadsResources = s.dataReadsResources || (s.dataReadsLocals && dp.locals.readsResources)
	s.dataReadsModules = s.dataReadsModules || (s.dataReadsLocals && dp.locals.readsModules)
	return s
}
