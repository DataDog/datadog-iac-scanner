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
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	maxHTTPRedirects       = 10
	maxConcurrentHTTPDials = 4
	httpScheme             = "http"
	httpsScheme            = "https"
)

// Synced with the IANA special-purpose address registries updated 2025-10-09.
var blockedSpecialUsePrefixes = func() []netip.Prefix {
	cidrs := []string{
		"0.0.0.0/8",
		"100.64.0.0/10",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"192.88.99.0/24",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"240.0.0.0/4",
		"64:ff9b::/96",
		"64:ff9b:1::/48",
		"100::/64",
		"100:0:0:1::/64",
		"2001::/23",
		"2001:db8::/32",
		"2002::/16",
		"3fff::/20",
		"5f00::/16",
	}
	prefixes := make([]netip.Prefix, len(cidrs))
	for i, cidr := range cidrs {
		prefixes[i] = netip.MustParsePrefix(cidr)
	}
	return prefixes
}()

type lookupNetIPFunc func(context.Context, string, string) ([]net.IP, error)
type dialContextFunc func(context.Context, string, string) (net.Conn, error)

type httpDestinationPolicy struct {
	hostAllowlist []string
	lookupNetIP   lookupNetIPFunc
	dial          dialContextFunc
}

func newHTTPDestinationPolicy(hostAllowlist []string) *httpDestinationPolicy {
	dialer := &net.Dialer{}
	return &httpDestinationPolicy{
		hostAllowlist: append([]string(nil), hostAllowlist...),
		lookupNetIP:   net.DefaultResolver.LookupIP,
		dial:          dialer.DialContext,
	}
}

func newPolicyHTTPClient(timeout time.Duration, hostAllowlist []string) *http.Client {
	policy := newHTTPDestinationPolicy(hostAllowlist)
	return newPolicyHTTPClientWithPolicy(timeout, policy)
}

func newPolicyHTTPClientWithPolicy(timeout time.Duration, policy *httpDestinationPolicy) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = policy.dialContext

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxHTTPRedirects {
				return fmt.Errorf("stopped after %d redirects", maxHTTPRedirects)
			}
			return policy.validateURL(req.Context(), req.URL)
		},
	}
}

func (p *httpDestinationPolicy) validateURL(ctx context.Context, target *url.URL) error {
	if target == nil {
		return errors.New("HTTP destination URL is missing")
	}
	if target.Scheme != httpScheme && target.Scheme != httpsScheme {
		return fmt.Errorf("HTTP destination scheme %q is not allowed", target.Scheme)
	}
	_, err := p.resolveHost(ctx, target.Hostname())
	return err
}

func (p *httpDestinationPolicy) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("parsing HTTP destination %q: %w", address, err)
	}
	addresses, err := p.resolveHost(ctx, host)
	if err != nil {
		return nil, err
	}

	type dialResult struct {
		conn net.Conn
		err  error
	}
	dialCtx, cancel := context.WithCancel(ctx)
	results := make(chan dialResult, len(addresses))
	targets := make(chan string, len(addresses))
	for _, address := range addresses {
		targets <- net.JoinHostPort(address.String(), port)
	}
	close(targets)
	for range min(maxConcurrentHTTPDials, len(addresses)) {
		go func() {
			for target := range targets {
				if err := dialCtx.Err(); err != nil {
					results <- dialResult{err: err}
					continue
				}
				conn, dialErr := p.dial(dialCtx, network, target)
				results <- dialResult{conn: conn, err: dialErr}
			}
		}()
	}

	dialErrs := make([]error, 0, len(addresses))
	for i := 0; i < len(addresses); i++ {
		result := <-results
		if result.err == nil {
			cancel()
			go func(remaining int) {
				for range remaining {
					if pending := <-results; pending.conn != nil {
						_ = pending.conn.Close()
					}
				}
			}(len(addresses) - i - 1)
			return result.conn, nil
		}
		dialErrs = append(dialErrs, result.err)
	}
	cancel()
	return nil, fmt.Errorf("dialing HTTP destination %q: %w", host, errors.Join(dialErrs...))
}

func (p *httpDestinationPolicy) resolveHost(ctx context.Context, host string) ([]netip.Addr, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return nil, errors.New("HTTP destination host is missing")
	}
	if !hostMatchesAllowlist(host, p.hostAllowlist) {
		return nil, fmt.Errorf("HTTP destination host %q is not in --module-host-allowlist", host)
	}

	if literal, err := netip.ParseAddr(host); err == nil {
		literal = literal.Unmap()
		if err := validatePublicAddress(literal); err != nil {
			return nil, fmt.Errorf("HTTP destination host %q: %w", host, err)
		}
		return []netip.Addr{literal}, nil
	}

	resolved, err := p.lookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolving HTTP destination host %q: %w", host, err)
	}
	if len(resolved) == 0 {
		return nil, fmt.Errorf("HTTP destination host %q resolved to no addresses", host)
	}

	addresses := make([]netip.Addr, 0, len(resolved))
	seen := make(map[netip.Addr]struct{}, len(resolved))
	for _, candidate := range resolved {
		addr, ok := netip.AddrFromSlice(candidate)
		if !ok {
			return nil, fmt.Errorf("HTTP destination host %q resolved to an invalid address", host)
		}
		addr = addr.Unmap()
		if err := validatePublicAddress(addr); err != nil {
			return nil, fmt.Errorf("HTTP destination host %q resolved to %s: %w", host, addr, err)
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		addresses = append(addresses, addr)
	}
	return addresses, nil
}

func hostMatchesAllowlist(host string, allowlist []string) bool {
	if len(allowlist) == 0 {
		return true
	}
	for _, allowed := range allowlist {
		allowed = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(allowed)), ".")
		if allowed != "" && (host == allowed || strings.HasSuffix(host, "."+allowed)) {
			return true
		}
	}
	return false
}

func validatePublicAddress(addr netip.Addr) error {
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsLoopback() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return fmt.Errorf("address %s is not a public unicast destination", addr)
	}
	for _, prefix := range blockedSpecialUsePrefixes {
		if prefix.Contains(addr) {
			return fmt.Errorf("address %s is in a special-use network", addr)
		}
	}
	return nil
}
