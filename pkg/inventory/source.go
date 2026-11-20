/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import (
	"net/url"
	"strings"
)

// keptSourceParams are the module source query parameters that say what is
// fetched. Every other parameter can carry a credential, such as sshkey,
// token or a signed URL's signature, and is dropped.
var keptSourceParams = map[string]bool{"ref": true, "depth": true, "archive": true}

// SanitizeSource returns a module source without the query parameters that
// can carry a secret. The parameters kept stay as written, in their order.
// URL credentials are removed upstream.
func SanitizeSource(source string) string {
	base, query, ok := strings.Cut(source, "?")
	if !ok {
		return source
	}
	var kept []string
	for _, part := range strings.Split(query, "&") {
		name, _, _ := strings.Cut(part, "=")
		if key, err := url.QueryUnescape(name); err == nil && keptSourceParams[key] {
			kept = append(kept, part)
		}
	}
	if len(kept) == 0 {
		return base
	}
	return base + "?" + strings.Join(kept, "&")
}
