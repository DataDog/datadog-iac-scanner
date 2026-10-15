/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package provider

// SourceProvider is the interface a service's source provider implements.
// GetBasePaths returns the base paths of the provider.
type SourceProvider interface {
	GetBasePaths() []string
}
