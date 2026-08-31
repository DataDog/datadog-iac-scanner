/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

func ModuleCallID(
	callerFile string,
	lineStart int,
	lineEnd int,
	moduleName string,
	source string,
	version string,
) string {
	return digestIdentity(
		filepath.Clean(callerFile),
		fmt.Sprint(lineStart),
		fmt.Sprint(lineEnd),
		strings.TrimSpace(moduleName),
		redactSourceCredentials(source),
		strings.TrimSpace(version),
	)
}

func ParsedModuleCallID(module *tfmodules.ParsedModule) string {
	if module == nil {
		return ""
	}
	return ModuleCallID(
		module.FileName,
		module.DefLine,
		module.DefEndLine,
		module.Name,
		module.Source,
		module.Version,
	)
}

func ModuleAcquisitionKey(source, version string) string {
	descriptor := DescribeModuleSource(source, version)
	identitySource := descriptor.NormalizedSource
	if descriptor.SourceType != sourceTypeRegistry && descriptor.SourceType != sourceTypeGit {
		identitySource = strings.TrimSpace(source)
	}
	return digestIdentity(
		descriptor.SourceType,
		identitySource,
		descriptor.RequestedVersion,
		descriptor.RequestedRef,
	)
}

func digestIdentity(values ...string) string {
	hasher := sha256.New()
	for _, value := range values {
		_, _ = hasher.Write([]byte(value))
		_, _ = hasher.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil))
}

// redactSourceCredentials strips embedded userinfo from git-getter source strings.
func redactSourceCredentials(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return ""
	}
	// Strip "scheme::" getter prefix so the underlying URL can be parsed.
	stripped := source
	if idx := strings.Index(source, "::"); idx >= 0 {
		stripped = source[idx+2:]
	}
	u, err := url.Parse(stripped)
	if err != nil || u.User == nil {
		return source
	}
	u.User = nil
	if idx := strings.Index(source, "::"); idx >= 0 {
		return source[:idx+2] + u.String()
	}
	return u.String()
}
