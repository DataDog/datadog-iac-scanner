/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package json

import (
	"strings"

	tfaddress "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"

	"github.com/tidwall/gjson"
)

// providerAddress maps a resource's provider_config_key, read in the config
// module at modulePath, to the address of the provider configuration the
// resource uses: "aws" or "aws.west" for a root module configuration.
//
// Terraform writes the key of the configuration a module call's providers
// map passes down, so most keys are already root addresses. A key scoped to a
// module, "<module>:<name>", names the module's own provider <name>: it is
// the module's configuration when the module declares one, "module.x:aws",
// and otherwise the parent's configuration of the same name. Older Terraform
// versions scope the key by the call name alone ("x:aws").
func (c *resourceChangeCorrelation) providerAddress(key, modulePath string) string {
	scope, local, scoped := strings.Cut(key, ":")
	if !scoped {
		return key
	}
	if strings.HasPrefix(scope, "module.") {
		modulePath = scope
	}
	for path := modulePath; path != ""; path = parentModulePath(path) {
		scopedKey := path + ":" + local
		if config := c.providerConfigs.Get(gjsonKey(scopedKey)); declaresProvider(&config) {
			return scopedKey
		}
	}
	return local
}

// parentModulePath is the config path of the module calling the module at
// path, "" for the root module.
func parentModulePath(path string) string {
	if i := strings.LastIndex(path, ".module."); i >= 0 {
		return path[:i]
	}
	return ""
}

// declaresProvider reports whether a provider_config entry is a provider
// block. Terraform also lists the providers a module only requires, with no
// configuration of their own.
func declaresProvider(config *gjson.Result) bool {
	return config.Get("expressions").Exists() || config.Get("alias").Exists()
}

// planProviderBlocks is the root module's provider.<name> section: the list of
// the bodies of its provider blocks, the default one and each alias, each
// with the key resources using it carry in _dd_meta.provider. As on an HCL
// scan, where a provider block of a module has no key, a configuration a
// module declares has no body here; resources using it name it in
// _dd_meta.provider as "module.<path>:<name>".
func planProviderBlocks(configs *gjson.Result) map[string]any {
	if !configs.IsObject() {
		return nil
	}
	out := map[string]any{}
	headers := configs.Get(linesKey)
	sectionLines := map[string]any{}
	hasLines := false
	configs.ForEach(func(key, config gjson.Result) bool {
		name := config.Get("name").String()
		if key.String() == linesKey || name == "" || config.Get("module_address").String() != "" || !declaresProvider(&config) {
			return true
		}
		expressions := config.Get("expressions")
		body, unknown := renderBody(&expressions)
		alias := ""
		if a := config.Get("alias"); a.Type == gjson.String {
			alias = a.String()
			body["alias"] = alias
			bodyLines, _ := body[linesKey].(map[string]any)
			if bodyLines == nil {
				bodyLines = map[string]any{}
			}
			copyLine(bodyLines, linesOf(&config), "alias", "alias")
			setLines(body, bodyLines)
		}
		configKey := tfaddress.ProviderKey(name, alias)
		meta := map[string]any{"address": tfaddress.ProviderAddr(name, alias), "provider": configKey}
		if unknown != nil {
			meta["unknown"] = unknown
		}
		body[ddMetaKey] = meta
		blocks, _ := out[name].([]any)
		out[name] = append(blocks, body)
		header := headers.Get(gjsonKey("_dd_"+key.String()) + "." + lineKey).Int()
		hasLines = hasLines || header > 0
		appendElementLine(sectionLines, name, header)
		return true
	})
	if len(out) == 0 {
		return nil
	}
	if hasLines {
		setLines(out, sectionLines)
	}
	return out
}

// appendElementLine adds an element at line to the line entry of the list
// under key k, whose own line is its first element's.
func appendElementLine(lines map[string]any, k string, line int64) {
	entry, _ := lines["_dd_"+k].(map[string]any)
	if entry == nil {
		entry = map[string]any{lineKey: line, arrKey: []any{}}
		lines["_dd_"+k] = entry
	}
	entry[arrKey] = append(entry[arrKey].([]any), map[string]any{defaultLineKey: map[string]any{lineKey: line}})
}
