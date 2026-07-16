/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package source

const scannerFindingLibrary = `package datadog

import rego.v1

finding(resource, relative_path) := {
	"_dd": {"id": resource._dd.id},
	"path": relative_path,
}
`

func ScannerFindingLibrary() RegoLibraries {
	return RegoLibraries{
		LibraryCode:      scannerFindingLibrary,
		LibraryInputData: "{}",
	}
}
