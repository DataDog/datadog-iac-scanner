/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package utils

// MergeMaps merges two maps
func MergeMaps(map1, map2 map[string]interface{}) {
	for key, value := range map2 {
		map1[key] = value
	}
}
