/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPDestinationPolicyRejectsNonPublicAddresses(t *testing.T) {
	tests := []string{
		"127.0.0.1",
		"10.0.0.1",
		"172.16.0.1",
		"192.168.0.1",
		"169.254.169.254",
		"100.64.0.1",
		"::1",
		"fe80::1",
		"fd00:ec2::254",
	}
	policy := newHTTPDestinationPolicy(nil)

	for _, address := range tests {
		t.Run(address, func(t *testing.T) {
			_, err := policy.resolveHost(t.Context(), address)
			if err == nil || !strings.Contains(err.Error(), "not a public unicast destination") &&
				!strings.Contains(err.Error(), "shared address space") {
				t.Fatalf("expected %s to be rejected, got %v", address, err)
			}
		})
	}
}

func TestHTTPDestinationPolicyRejectsHostnameWithPrivateAnswer(t *testing.T) {
	policy := newHTTPDestinationPolicy(nil)
	policy.lookupNetIP = func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{
			net.ParseIP("93.184.216.34"),
			net.ParseIP("169.254.169.254"),
		}, nil
	}

	_, err := policy.resolveHost(t.Context(), "modules.example.com")

	if err == nil || !strings.Contains(err.Error(), "169.254.169.254") {
		t.Fatalf("expected mixed DNS answer to be rejected, got %v", err)
	}
}

func TestHTTPDestinationPolicyPinsValidatedAddress(t *testing.T) {
	policy := newHTTPDestinationPolicy(nil)
	policy.lookupNetIP = func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}
	var dialed string
	policy.dial = func(_ context.Context, _, address string) (net.Conn, error) {
		dialed = address
		client, server := net.Pipe()
		t.Cleanup(func() {
			_ = client.Close()
			_ = server.Close()
		})
		return client, nil
	}

	conn, err := policy.dialContext(t.Context(), "tcp", "modules.example.com:443")

	if err != nil {
		t.Fatalf("dialContext: %v", err)
	}
	_ = conn.Close()
	if dialed != "93.184.216.34:443" {
		t.Fatalf("dialed %q, want validated IP", dialed)
	}
}

func TestHTTPDestinationPolicyDialsValidatedAddressesConcurrently(t *testing.T) {
	policy := newHTTPDestinationPolicy(nil)
	policy.lookupNetIP = func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{
			net.ParseIP("2001:db8::1"),
			net.ParseIP("93.184.216.34"),
		}, nil
	}
	firstCanceled := make(chan struct{})
	policy.dial = func(ctx context.Context, _, address string) (net.Conn, error) {
		if strings.HasPrefix(address, "[2001:db8::1]") {
			<-ctx.Done()
			close(firstCanceled)
			return nil, ctx.Err()
		}
		client, server := net.Pipe()
		t.Cleanup(func() {
			_ = client.Close()
			_ = server.Close()
		})
		return client, nil
	}

	conn, err := policy.dialContext(t.Context(), "tcp", "modules.example.com:443")

	if err != nil {
		t.Fatalf("dialContext: %v", err)
	}
	_ = conn.Close()
	select {
	case <-firstCanceled:
	case <-time.After(time.Second):
		t.Fatal("slower validated address was not canceled")
	}
}

func TestHTTPDestinationPolicyBoundsConcurrentDials(t *testing.T) {
	policy := newHTTPDestinationPolicy(nil)
	policy.lookupNetIP = func(context.Context, string, string) ([]net.IP, error) {
		addresses := make([]net.IP, 12)
		for i := range addresses {
			addresses[i] = net.IPv4(192, 0, 2, byte(i+1))
		}
		return addresses, nil
	}
	var inFlight atomic.Int32
	var peak atomic.Int32
	policy.dial = func(context.Context, string, string) (net.Conn, error) {
		current := inFlight.Add(1)
		for {
			previous := peak.Load()
			if current <= previous || peak.CompareAndSwap(previous, current) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		inFlight.Add(-1)
		return nil, errors.New("unreachable")
	}

	_, err := policy.dialContext(t.Context(), "tcp", "modules.example.com:443")

	if err == nil {
		t.Fatal("expected all addresses to fail")
	}
	if got := peak.Load(); got > maxConcurrentHTTPDials {
		t.Fatalf("peak concurrent dials = %d, want at most %d", got, maxConcurrentHTTPDials)
	}
}

func TestHTTPDestinationPolicyDeduplicatesDNSAnswers(t *testing.T) {
	policy := newHTTPDestinationPolicy(nil)
	policy.lookupNetIP = func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{
			net.ParseIP("93.184.216.34"),
			net.ParseIP("93.184.216.34"),
		}, nil
	}
	var calls atomic.Int32
	policy.dial = func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("unreachable")
	}

	_, err := policy.dialContext(t.Context(), "tcp", "modules.example.com:443")

	if err == nil {
		t.Fatal("expected address to fail")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("dial calls = %d, want one per unique address", got)
	}
}

func TestHTTPDestinationPolicyAppliesHostAllowlist(t *testing.T) {
	policy := newHTTPDestinationPolicy([]string{"example.com"})
	policy.lookupNetIP = func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}

	if _, err := policy.resolveHost(t.Context(), "modules.example.com"); err != nil {
		t.Fatalf("expected subdomain to pass allowlist: %v", err)
	}
	if _, err := policy.resolveHost(t.Context(), "example.net"); err == nil {
		t.Fatal("expected unrelated host to fail allowlist")
	}
}

func TestPolicyHTTPClientValidatesRedirectDestination(t *testing.T) {
	client := newPolicyHTTPClient(time.Second, nil)
	redirectURL, err := url.Parse("http://169.254.169.254/latest/meta-data")
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{URL: redirectURL}

	err = client.CheckRedirect(req, []*http.Request{{}})

	if err == nil || !strings.Contains(err.Error(), "not a public unicast destination") {
		t.Fatalf("expected redirect to metadata endpoint to be rejected, got %v", err)
	}
}

func TestPolicyHTTPClientLimitsRedirects(t *testing.T) {
	client := newPolicyHTTPClient(time.Second, nil)
	req := &http.Request{URL: &url.URL{Scheme: "https", Host: "example.com"}}
	via := make([]*http.Request, maxHTTPRedirects)

	err := client.CheckRedirect(req, via)

	if err == nil || !strings.Contains(err.Error(), "stopped after 10 redirects") {
		t.Fatalf("expected redirect limit error, got %v", err)
	}
}
