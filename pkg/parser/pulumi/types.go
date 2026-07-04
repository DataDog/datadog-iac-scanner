/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package pulumi

import "strings"

// pythonPkgToProvider maps a Python pulumi provider package name to its Pulumi
// type token prefix (e.g. "pulumi_aws" → "aws").
var pythonPkgToProvider = map[string]string{
	"pulumi_aws":              "aws",
	"pulumi_aws_native":       "aws-native",
	"pulumi_azure":            "azure",
	"pulumi_azure_native":     "azure-native",
	"pulumi_gcp":              "gcp",
	"pulumi_google_native":    "google-native",
	"pulumi_kubernetes":       "kubernetes",
	"pulumi_digitalocean":     "digitalocean",
	"pulumi_cloudflare":       "cloudflare",
	"pulumi_random":           "random",
	"pulumi_tls":              "tls",
	"pulumi_github":           "github",
	"pulumi_datadog":          "datadog",
	"pulumi_vault":            "vault",
	"pulumi_docker":           "docker",
	"pulumi_postgresql":       "postgresql",
	"pulumi_mysql":            "mysql",
	"pulumi_mongodbatlas":     "mongodbatlas",
	"pulumi_newrelic":         "newrelic",
	"pulumi_pagerduty":        "pagerduty",
	"pulumi_alicloud":         "alicloud",
	"pulumi_openstack":        "openstack",
	"pulumi_azure_devops":     "azuredevops",
	"pulumi_okta":             "okta",
	"pulumi_auth0":            "auth0",
	"pulumi_snowflake":        "snowflake",
	"pulumi_sumologic":        "sumologic",
	"pulumi_eks":              "eks",
	"pulumi_awsx":             "awsx",
}

// npmPkgToProvider maps an NPM @pulumi/<name> package to its type token prefix.
var npmPkgToProvider = map[string]string{
	"@pulumi/aws":            "aws",
	"@pulumi/aws-native":     "aws-native",
	"@pulumi/azure":          "azure",
	"@pulumi/azure-native":   "azure-native",
	"@pulumi/gcp":            "gcp",
	"@pulumi/google-native":  "google-native",
	"@pulumi/kubernetes":     "kubernetes",
	"@pulumi/digitalocean":   "digitalocean",
	"@pulumi/cloudflare":     "cloudflare",
	"@pulumi/random":         "random",
	"@pulumi/tls":            "tls",
	"@pulumi/github":         "github",
	"@pulumi/datadog":        "datadog",
	"@pulumi/vault":          "vault",
	"@pulumi/docker":         "docker",
	"@pulumi/postgresql":     "postgresql",
	"@pulumi/mysql":          "mysql",
	"@pulumi/mongodbatlas":   "mongodbatlas",
	"@pulumi/newrelic":       "newrelic",
	"@pulumi/pagerduty":      "pagerduty",
	"@pulumi/alicloud":       "alicloud",
	"@pulumi/openstack":      "openstack",
	"@pulumi/azure-devops":   "azuredevops",
	"@pulumi/okta":           "okta",
	"@pulumi/auth0":          "auth0",
	"@pulumi/snowflake":      "snowflake",
	"@pulumi/eks":            "eks",
	"@pulumi/awsx":           "awsx",
}

// PythonPkgToProvider looks up the Pulumi type token prefix for a Python package.
func PythonPkgToProvider(pkg string) (string, bool) {
	p, ok := pythonPkgToProvider[pkg]
	return p, ok
}

// NpmPkgToProvider looks up the Pulumi type token prefix for an NPM package.
func NpmPkgToProvider(pkg string) (string, bool) {
	p, ok := npmPkgToProvider[pkg]
	return p, ok
}

// GoImportToProviderModule parses a Go import path of the form
// "github.com/pulumi/pulumi-<provider>/sdk/.../go/<provider>/<module>"
// and returns (provider, module). Returns ("", "") if the path is not a
// recognised Pulumi provider import.
func GoImportToProviderModule(importPath string) (provider, module string) {
	// Must be under github.com/pulumi/pulumi-<provider>/
	const prefix = "github.com/pulumi/pulumi-"
	if !strings.HasPrefix(importPath, prefix) {
		return "", ""
	}
	rest := importPath[len(prefix):]
	// rest = "<provider>/sdk/.../go/<provider>/<module>" or similar
	slashIdx := strings.Index(rest, "/")
	if slashIdx < 0 {
		return "", ""
	}
	rawProvider := rest[:slashIdx] // e.g. "aws", "azure-native", "kubernetes"

	// Last path segment is the Go package name, which is the Pulumi module.
	segments := strings.Split(importPath, "/")
	mod := segments[len(segments)-1]

	// The Go package for the top-level provider SDK (e.g. ".../go/aws") has
	// module == provider name; skip those — callers need the sub-module.
	// We still return them; callers decide what to do.
	return rawProvider, mod
}

// SnakeToCamel converts a Python-style snake_case identifier to camelCase so
// that property names extracted from Python keyword arguments match the
// camelCase names expected by Pulumi Rego rules.
//
//	"publicly_accessible" → "publiclyAccessible"
//	"monitoring"          → "monitoring"  (no change, no underscores)
func SnakeToCamel(s string) string {
	parts := strings.Split(s, "_")
	for i := 1; i < len(parts); i++ {
		if len(parts[i]) > 0 {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, "")
}

// BuildDDLines builds the minimal _dd_lines map for a single line, keyed by
// field names.  Returns a map[string]interface{} suitable for embedding as
// "_dd_lines".
func BuildDDLines(defaultLine int, fields map[string]int) map[string]interface{} {
	out := make(map[string]interface{}, len(fields)+1)
	out["_dd__default"] = map[string]interface{}{"_dd_line": defaultLine}
	for name, line := range fields {
		out["_dd_"+name] = map[string]interface{}{"_dd_line": line}
	}
	return out
}
