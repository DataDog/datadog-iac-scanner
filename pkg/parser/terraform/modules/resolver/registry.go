/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	goversion "github.com/hashicorp/go-version"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

const (
	defaultRegistryHost = "registry.terraform.io"

	discoveryResponseLimit = 64 * 1024
	versionsResponseLimit  = 128 * 1024

	publicRegistrySourceParts  = 3 // namespace/name/provider
	privateRegistrySourceParts = 4 // host/namespace/name/provider
)

func appendGetterSubdir(getterURL, subdir string) string {
	if q := strings.Index(getterURL, "?"); q != -1 {
		return getterURL[:q] + "//" + subdir + getterURL[q:]
	}
	return getterURL + "//" + subdir
}

func splitGetterSubdir(getterURL string) (packageURL, subdir string) {
	queryStart := len(getterURL)
	if query := strings.IndexByte(getterURL, '?'); query >= 0 {
		queryStart = query
	}
	searchStart := 0
	if getterPrefix := strings.Index(getterURL[:queryStart], "::"); getterPrefix >= 0 {
		searchStart = getterPrefix + 2
	}
	if scheme := strings.Index(getterURL[searchStart:queryStart], "://"); scheme >= 0 {
		searchStart += scheme + 3
	}
	subdirMarker := strings.Index(getterURL[searchStart:queryStart], "//")
	if subdirMarker < 0 {
		return getterURL, ""
	}
	subdirMarker += searchStart
	subdir = strings.TrimPrefix(getterURL[subdirMarker+2:queryStart], "/")
	if subdir == "" {
		return getterURL, ""
	}
	return getterURL[:subdirMarker] + getterURL[queryStart:], subdir
}

// parseRegistrySource splits public (ns/name/provider) or private (host/ns/name/provider) sources.
func parseRegistrySource(source string) (host, namespace, name, provider string, err error) {
	source, _, _ = strings.Cut(source, "//")
	parts := strings.Split(source, "/")
	switch len(parts) {
	case publicRegistrySourceParts:
		return defaultRegistryHost, parts[0], parts[1], parts[2], nil
	case privateRegistrySourceParts:
		return parts[0], parts[1], parts[2], parts[3], nil
	default:
		return "", "", "", "", fmt.Errorf("invalid registry source %q: expected namespace/name/provider", source)
	}
}

func registrySubdir(source string) string {
	_, subdir, ok := strings.Cut(source, "//")
	if !ok {
		return ""
	}
	return strings.TrimPrefix(subdir, "/")
}

type serviceDiscovery struct {
	ModulesV1 string `json:"modules.v1"`
}

func discoverModulesEndpoint(ctx context.Context, client *http.Client, baseURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/.well-known/terraform.json", http.NoBody)
	if err != nil {
		return "", err
	}
	addRegistryToken(req, req.URL.Hostname())
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, discoveryResponseLimit))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery returned HTTP %d", resp.StatusCode)
	}
	var sd serviceDiscovery
	if err := json.Unmarshal(body, &sd); err != nil {
		return "", fmt.Errorf("parsing discovery response: %w", err)
	}
	if sd.ModulesV1 == "" {
		return "", fmt.Errorf("modules.v1 endpoint not found in discovery response")
	}
	if !strings.HasSuffix(sd.ModulesV1, "/") {
		sd.ModulesV1 += "/"
	}
	// Resolve relative service URLs (e.g. "terraform/modules/v1/" or "/api/modules/v1/")
	// against the discovery base URL per the Terraform registry protocol spec.
	if ref, err := url.Parse(sd.ModulesV1); err == nil && !ref.IsAbs() {
		base, _ := url.Parse(baseURL)
		return base.ResolveReference(ref).String(), nil
	}
	return sd.ModulesV1, nil
}

type versionsResponse struct {
	Modules []struct {
		Versions []struct {
			Version string `json:"version"`
		} `json:"versions"`
	} `json:"modules"`
}

// resolveRegistryVersion picks the highest published version satisfying constraint (empty → latest).
func resolveRegistryVersion(
	ctx context.Context, client *http.Client,
	modulesV1, namespace, name, provider, constraint string,
) (string, error) {
	rawURL := fmt.Sprintf("%s%s/%s/%s/versions", modulesV1, namespace, name, provider)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return "", err
	}
	addRegistryToken(req, req.URL.Hostname())
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, versionsResponseLimit))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("versions endpoint returned HTTP %d", resp.StatusCode)
	}
	var vr versionsResponse
	if err := json.Unmarshal(body, &vr); err != nil {
		return "", fmt.Errorf("parsing versions response: %w", err)
	}
	if len(vr.Modules) == 0 || len(vr.Modules[0].Versions) == 0 {
		return "", fmt.Errorf("no versions published")
	}

	if constraint == "" {
		best, ok := selectBestVersion(vr, nil)
		if !ok {
			return "", fmt.Errorf("no parseable versions published")
		}
		return best.Original(), nil
	}

	cs, err := goversion.NewConstraint(constraint)
	if err != nil {
		return "", fmt.Errorf("invalid version constraint %q: %w", constraint, err)
	}
	best, ok := selectBestVersion(vr, cs)
	if !ok {
		return "", fmt.Errorf("no published version satisfies constraint %q", constraint)
	}
	return best.Original(), nil
}

// selectBestVersion returns the highest published version satisfying cs (nil = any parseable version).
func selectBestVersion(vr versionsResponse, cs goversion.Constraints) (*goversion.Version, bool) {
	var best *goversion.Version
	for _, mod := range vr.Modules {
		for _, v := range mod.Versions {
			sv, err := goversion.NewVersion(v.Version)
			if err != nil || (cs != nil && !cs.Check(sv)) {
				continue
			}
			if best == nil || sv.GreaterThan(best) {
				best = sv
			}
		}
	}
	return best, best != nil
}

func registryDownloadURL(
	ctx context.Context, client *http.Client,
	modulesV1, namespace, name, provider, version, host string,
) (string, error) {
	rawURL := fmt.Sprintf("%s%s/%s/%s/%s/download", modulesV1, namespace, name, provider, version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return "", &tfmodules.UnresolvedError{Reason: "building download request: " + err.Error()}
	}
	addRegistryToken(req, host)
	resp, err := client.Do(req)
	if err != nil {
		return "", &tfmodules.UnresolvedError{Reason: "download request failed: " + err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
	// 204/OK + X-Terraform-Get → getter URL.
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", &tfmodules.UnresolvedError{
			Reason: fmt.Sprintf("download endpoint returned HTTP %d", resp.StatusCode),
		}
	}
	getterURL := resp.Header.Get("X-Terraform-Get")
	if getterURL == "" {
		return "", &tfmodules.UnresolvedError{Reason: "registry did not return X-Terraform-Get header"}
	}
	// Resolve relative URLs (e.g. /archives/mod.zip) against the download endpoint.
	if ref, err := url.Parse(getterURL); err == nil && !ref.IsAbs() {
		getterURL = req.URL.ResolveReference(ref).String()
	}
	return getterURL, nil
}

// isBareVersion reports whether s is an exact semver (no constraint operators).
func isBareVersion(s string) bool {
	for _, c := range s {
		if c != '.' && c != '-' && c != '+' && (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return s != ""
}

// addRegistryToken sets Authorization from TF_TOKEN_<host> (dots/hyphens → underscores).
func addRegistryToken(req *http.Request, rawHost string) {
	envKey := "TF_TOKEN_" + strings.NewReplacer(".", "_", "-", "_").Replace(rawHost)
	if tok := os.Getenv(envKey); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
}
