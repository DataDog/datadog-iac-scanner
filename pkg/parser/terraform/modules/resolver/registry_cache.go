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
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

// deadHostTTL is how long a registry discovery failure is remembered across runs.
const deadHostTTL = 24 * time.Hour

func deadHostsFilePath() string {
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		base = filepath.Join(home, ".cache")
	}
	return filepath.Join(base, "datadog-iac-scanner", "dead-registry-hosts.json")
}

// loadDeadHosts reads hosts whose registry discovery has previously failed.
// Entries older than deadHostTTL are ignored.
func loadDeadHosts() map[string]int64 {
	p := deadHostsFilePath()
	if p == "" {
		return nil
	}
	data, err := os.ReadFile(filepath.Clean(p)) //nolint:gosec
	if err != nil {
		return nil
	}
	var m map[string]int64
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	return m
}

// persistDeadHost records host as unreachable, pruning entries older than deadHostTTL.
// Runs in a goroutine so it never blocks the hot path.
func persistDeadHost(host string) {
	p := deadHostsFilePath()
	if p == "" {
		return
	}
	p = filepath.Clean(p)
	existing := make(map[string]int64)
	if data, err := os.ReadFile(p); err == nil { //nolint:gosec
		_ = json.Unmarshal(data, &existing)
	}
	now := time.Now().Unix()
	cutoff := now - int64(deadHostTTL.Seconds())
	for h, ts := range existing {
		if ts < cutoff {
			delete(existing, h)
		}
	}
	existing[host] = now
	data, err := json.Marshal(existing)
	if err != nil {
		return
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, cacheFilePerms); err != nil {
		return
	}
	_ = os.Rename(tmp, p)
}

// registryCache caches per-scan registry API calls (including failures).
type registryCache struct {
	client *http.Client

	discMu     sync.RWMutex
	discMap    map[string]string // host → modulesV1 URL
	discErrMap map[string]error  // host → discovery failure
	discSF     singleflight.Group

	verMu     sync.RWMutex
	verMap    map[string]string // cacheKey(source, constraint) → resolved bare version
	verErrMap map[string]error  // cacheKey(source, constraint) → resolution failure
	verSF     singleflight.Group

	dlMu     sync.RWMutex
	dlMap    map[string]string // cacheKey(source, version) → X-Terraform-Get getter URL
	dlErrMap map[string]error  // cacheKey(source, version) → download failure
	dlSF     singleflight.Group
}

func NewRegistryCache(timeout time.Duration) *registryCache {
	c := &registryCache{
		client:     &http.Client{Timeout: timeout},
		discMap:    make(map[string]string),
		discErrMap: make(map[string]error),
		verMap:     make(map[string]string),
		verErrMap:  make(map[string]error),
		dlMap:      make(map[string]string),
		dlErrMap:   make(map[string]error),
	}
	// Pre-populate known-dead hosts from previous runs so we skip DNS lookups
	// for registries that were unreachable last time (within deadHostTTL).
	now := time.Now().Unix()
	cutoff := now - int64(deadHostTTL.Seconds())
	for host, ts := range loadDeadHosts() {
		if ts >= cutoff {
			c.discErrMap[host] = fmt.Errorf("registry host unreachable (cached from previous run; clear %s to retry)", deadHostsFilePath())
		}
	}
	return c
}

func (c *registryCache) modulesV1(ctx context.Context, host string) (string, error) {
	c.discMu.RLock()
	if ep, ok := c.discMap[host]; ok {
		c.discMu.RUnlock()
		return ep, nil
	}
	if cachedErr, ok := c.discErrMap[host]; ok {
		c.discMu.RUnlock()
		return "", cachedErr
	}
	c.discMu.RUnlock()

	v, err, _ := c.discSF.Do(host, func() (interface{}, error) {
		ep, err := discoverModulesEndpoint(ctx, c.client, "https://"+host)
		if err != nil {
			c.discMu.Lock()
			c.discErrMap[host] = err
			c.discMu.Unlock()
			go persistDeadHost(host) // async, non-critical
			return "", err
		}
		c.discMu.Lock()
		c.discMap[host] = ep
		c.discMu.Unlock()
		return ep, nil
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

func (c *registryCache) resolvedVersion(ctx context.Context, ep, host, namespace, name, provider, constraint string) (string, error) {
	key := host + "\x00" + namespace + "/" + name + "/" + provider + "\x00" + constraint

	c.verMu.RLock()
	if v, ok := c.verMap[key]; ok {
		c.verMu.RUnlock()
		return v, nil
	}
	if cachedErr, ok := c.verErrMap[key]; ok {
		c.verMu.RUnlock()
		return "", cachedErr
	}
	c.verMu.RUnlock()

	v, err, _ := c.verSF.Do(key, func() (interface{}, error) {
		resolved, err := resolveRegistryVersion(ctx, c.client, ep, namespace, name, provider, constraint)
		if err != nil {
			c.verMu.Lock()
			c.verErrMap[key] = err
			c.verMu.Unlock()
			return "", err
		}
		c.verMu.Lock()
		c.verMap[key] = resolved
		c.verMu.Unlock()
		return resolved, nil
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

func (c *registryCache) downloadURL(ctx context.Context, ep, host, namespace, name, provider, version string) (string, error) {
	key := host + "\x00" + namespace + "/" + name + "/" + provider + "@" + version

	c.dlMu.RLock()
	if v, ok := c.dlMap[key]; ok {
		c.dlMu.RUnlock()
		return v, nil
	}
	if cachedErr, ok := c.dlErrMap[key]; ok {
		c.dlMu.RUnlock()
		return "", cachedErr
	}
	c.dlMu.RUnlock()

	v, err, _ := c.dlSF.Do(key, func() (interface{}, error) {
		dlURL, err := registryDownloadURL(ctx, c.client, ep, namespace, name, provider, version, host)
		if err != nil {
			c.dlMu.Lock()
			c.dlErrMap[key] = err
			c.dlMu.Unlock()
			return "", err
		}
		c.dlMu.Lock()
		c.dlMap[key] = dlURL
		c.dlMu.Unlock()
		return dlURL, nil
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

func (c *registryCache) resolveConcreteVersion(ctx context.Context, source, version string) (string, error) {
	host, namespace, name, provider, parseErr := parseRegistrySource(source)
	if parseErr != nil {
		return "", &tfmodules.UnresolvedError{Reason: parseErr.Error()}
	}

	if version != "" && isBareVersion(version) {
		return version, nil
	}

	ep, err := c.modulesV1(ctx, host)
	if err != nil {
		return "", &tfmodules.UnresolvedError{Reason: fmt.Sprintf("registry discovery for %s: %v", host, err)}
	}

	resolved, resolveErr := c.resolvedVersion(ctx, ep, host, namespace, name, provider, version)
	if resolveErr != nil {
		return "", &tfmodules.UnresolvedError{
			Reason: fmt.Sprintf("could not resolve version for %s/%s/%s: %v", namespace, name, provider, resolveErr),
		}
	}
	contextLogger := logger.FromContext(ctx)
	if version == "" {
		contextLogger.Warn().Msgf("module %s/%s/%s: no version pinned; resolved to %s", namespace, name, provider, resolved)
	} else {
		contextLogger.Debug().Msgf("module %s/%s/%s: constraint %q resolved to %s", namespace, name, provider, version, resolved)
	}
	return resolved, nil
}

func (c *registryCache) resolveGetterURL(ctx context.Context, source, concreteVersion string) (string, error) {
	host, namespace, name, provider, parseErr := parseRegistrySource(source)
	if parseErr != nil {
		return "", &tfmodules.UnresolvedError{Reason: parseErr.Error()}
	}

	ep, err := c.modulesV1(ctx, host)
	if err != nil {
		return "", &tfmodules.UnresolvedError{Reason: fmt.Sprintf("registry discovery for %s: %v", host, err)}
	}

	dlURL, err := c.downloadURL(ctx, ep, host, namespace, name, provider, concreteVersion)
	if err != nil {
		return "", err
	}

	if subdir := registrySubdir(source); subdir != "" {
		dlURL = appendGetterSubdir(dlURL, subdir)
	}

	return dlURL, nil
}
