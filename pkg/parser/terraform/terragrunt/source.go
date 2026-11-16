/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terragrunt

import (
	"net/url"
	"strings"
)

const tfrScheme = "tfr://"

// moduleSource turns a terraform.source into a Terraform module source and
// version. Terragrunt's tfr:// registry URLs become registry addresses:
// tfr:///ns/name/provider//sub?version=1.0 is ns/name/provider//sub at 1.0,
// and tfr://host/ns/name/provider keeps its host. Other sources are go-getter
// sources Terraform reads as they are.
func moduleSource(source string) (address, version string) {
	if !strings.HasPrefix(source, tfrScheme) {
		return source, ""
	}
	parsed, err := url.Parse(source)
	if err != nil {
		return source, ""
	}
	address = strings.TrimPrefix(parsed.Path, "/")
	if parsed.Host != "" {
		address = parsed.Host + "/" + address
	}
	return address, parsed.Query().Get("version")
}
