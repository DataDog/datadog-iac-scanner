/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package metaargs names the arguments and nested blocks of a resource, data
// or ephemeral block that configure Terraform rather than the resource. A plan
// lists none of them among a resource's values, unknown values or expressions.
package metaargs

var names = map[string]bool{
	"count":       true,
	"for_each":    true,
	"depends_on":  true,
	"provider":    true,
	"lifecycle":   true,
	"provisioner": true,
	"connection":  true,
}

// moduleNames are the meta-arguments of a module call.
var moduleNames = map[string]bool{
	"count":      true,
	"for_each":   true,
	"depends_on": true,
	"providers":  true,
}

// outputNames are the meta-arguments of an output block.
var outputNames = map[string]bool{
	"depends_on": true,
}

// Is reports whether name is a meta-argument or meta-block of a resource.
func Is(name string) bool {
	return names[name]
}

// Hidden reports whether name is a meta-argument a resource's document leaves
// out of its body: all of them but provisioner blocks, which stay in it.
func Hidden(name string) bool {
	return names[name] && name != "provisioner"
}

// IsModule reports whether name is a meta-argument of a module call, which
// the call's document leaves out of its body.
func IsModule(name string) bool {
	return moduleNames[name]
}

// IsOutput reports whether name is a meta-argument of an output block, which
// the output's document leaves out of its body.
func IsOutput(name string) bool {
	return outputNames[name]
}
