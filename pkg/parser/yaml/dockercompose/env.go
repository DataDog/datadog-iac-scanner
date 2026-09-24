/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package dockercompose

import (
	"strings"
)

// ParseEnvFile parses a Compose .env file into a variable map. It follows the
// Compose spec: KEY=VAL lines, blank lines and #-comments ignored, an
// optional "export " prefix, and surrounding quotes stripped (single-quoted
// values are literal, double-quoted values unescape \n, \t and \\).
// No interpolation happens inside .env files themselves.
func ParseEnvFile(content []byte) map[string]string {
	env := make(map[string]string)
	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		if key == "" {
			continue
		}
		env[key] = unquoteEnvValue(strings.TrimSpace(line[eq+1:]))
	}
	return env
}

// unquoteEnvValue strips one pair of matching surrounding quotes. Double-quoted
// values get \n, \t and \\ unescaped; single-quoted values stay literal.
func unquoteEnvValue(v string) string {
	if len(v) >= 2 {
		switch v[0] {
		case '\'':
			if v[len(v)-1] == '\'' {
				return v[1 : len(v)-1]
			}
		case '"':
			if v[len(v)-1] == '"' {
				inner := v[1 : len(v)-1]
				inner = strings.ReplaceAll(inner, `\n`, "\n")
				inner = strings.ReplaceAll(inner, `\t`, "\t")
				return strings.ReplaceAll(inner, `\\`, `\`)
			}
		}
	}
	return v
}
