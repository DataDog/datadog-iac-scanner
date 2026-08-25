/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

const defaultRegistryFailureBackoff = 30 * time.Second

type cachedFailure struct {
	err    error
	expiry time.Time
}

type registryCache struct {
	client *http.Client

	now     func() time.Time
	backoff time.Duration

	discMu     sync.RWMutex
	discMap    map[string]string
	discErrMap map[string]cachedFailure
	discSF     singleflight.Group

	verMu     sync.RWMutex
	verMap    map[string]string
	verErrMap map[string]cachedFailure
	verSF     singleflight.Group

	dlMu     sync.RWMutex
	dlMap    map[string]string
	dlErrMap map[string]cachedFailure
	dlSF     singleflight.Group
}

func NewRegistryCache(timeout time.Duration, hostAllowlist ...string) *registryCache {
	return &registryCache{
		client:     newPolicyHTTPClient(timeout, hostAllowlist),
		discMap:    make(map[string]string),
		discErrMap: make(map[string]cachedFailure),
		verMap:     make(map[string]string),
		verErrMap:  make(map[string]cachedFailure),
		dlMap:      make(map[string]string),
		dlErrMap:   make(map[string]cachedFailure),
		backoff:    defaultRegistryFailureBackoff,
	}
}

func (c *registryCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *registryCache) failureBackoff() time.Duration {
	if c.backoff > 0 {
		return c.backoff
	}
	return defaultRegistryFailureBackoff
}

func (c *registryCache) lookupFailure(mu *sync.RWMutex, failures map[string]cachedFailure, key string) (error, bool) {
	mu.RLock()
	cached, ok := failures[key]
	mu.RUnlock()
	if !ok {
		return nil, false
	}
	if c.clock().After(cached.expiry) {
		mu.Lock()
		if current, still := failures[key]; still && current.expiry.Equal(cached.expiry) {
			delete(failures, key)
		}
		mu.Unlock()
		return nil, false
	}
	return cached.err, true
}

func (c *registryCache) rememberFailure(mu *sync.RWMutex, failures map[string]cachedFailure, key string, err error) {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return
	}
	mu.Lock()
	failures[key] = cachedFailure{err: err, expiry: c.clock().Add(c.failureBackoff())}
	mu.Unlock()
}

func (c *registryCache) modulesV1(ctx context.Context, host string) (string, error) {
	c.discMu.RLock()
	if ep, ok := c.discMap[host]; ok {
		c.discMu.RUnlock()
		return ep, nil
	}
	c.discMu.RUnlock()
	if cachedErr, ok := c.lookupFailure(&c.discMu, c.discErrMap, host); ok {
		return "", cachedErr
	}

	v, err, _ := c.discSF.Do(host, func() (interface{}, error) {
		ep, err := discoverModulesEndpoint(ctx, c.client, "https://"+host)
		if err != nil {
			c.rememberFailure(&c.discMu, c.discErrMap, host, err)
			return "", err
		}
		c.discMu.Lock()
		c.discMap[host] = ep
		delete(c.discErrMap, host)
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
	c.verMu.RUnlock()
	if cachedErr, ok := c.lookupFailure(&c.verMu, c.verErrMap, key); ok {
		return "", cachedErr
	}

	v, err, _ := c.verSF.Do(key, func() (interface{}, error) {
		resolved, err := resolveRegistryVersion(ctx, c.client, ep, namespace, name, provider, constraint)
		if err != nil {
			c.rememberFailure(&c.verMu, c.verErrMap, key, err)
			return "", err
		}
		c.verMu.Lock()
		c.verMap[key] = resolved
		delete(c.verErrMap, key)
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
	c.dlMu.RUnlock()
	if cachedErr, ok := c.lookupFailure(&c.dlMu, c.dlErrMap, key); ok {
		return "", cachedErr
	}

	v, err, _ := c.dlSF.Do(key, func() (interface{}, error) {
		dlURL, err := registryDownloadURL(ctx, c.client, ep, namespace, name, provider, version, host)
		if err != nil {
			c.rememberFailure(&c.dlMu, c.dlErrMap, key, err)
			return "", err
		}
		c.dlMu.Lock()
		c.dlMap[key] = dlURL
		delete(c.dlErrMap, key)
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
