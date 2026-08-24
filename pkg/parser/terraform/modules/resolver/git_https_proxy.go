/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
)

type gitHTTPSProxy struct {
	listener net.Listener
	server   *http.Server
	mu       sync.Mutex
	tunnels  map[net.Conn]struct{}
	closed   bool
}

func startGitHTTPSProxy(policy *httpDestinationPolicy) (*gitHTTPSProxy, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("starting git HTTPS proxy: %w", err)
	}
	proxy := &gitHTTPSProxy{
		listener: listener,
		tunnels:  make(map[net.Conn]struct{}),
	}
	proxy.server = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			proxy.handle(policy, w, req)
		}),
		ReadHeaderTimeout: DefaultFetchTimeout,
	}
	go func() {
		_ = proxy.server.Serve(listener)
	}()
	return proxy, nil
}

func (p *gitHTTPSProxy) URL() string {
	return "http://" + p.listener.Addr().String()
}

func (p *gitHTTPSProxy) Close() error {
	err := p.server.Close()
	p.mu.Lock()
	p.closed = true
	for conn := range p.tunnels {
		_ = conn.Close()
	}
	p.tunnels = make(map[net.Conn]struct{})
	p.mu.Unlock()
	return err
}

func (p *gitHTTPSProxy) handle(policy *httpDestinationPolicy, w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodConnect {
		http.Error(w, "only HTTPS CONNECT is allowed", http.StatusForbidden)
		return
	}
	target := req.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		http.Error(w, "invalid CONNECT destination", http.StatusBadRequest)
		return
	}
	upstream, err := policy.dialContext(req.Context(), "tcp", target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	defer func() { _ = upstream.Close() }()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "proxy connection cannot be established", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = client.Close() }()
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	p.track(client, upstream)
	defer p.untrack(client, upstream)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, buffered)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
		if tcp, ok := client.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	wg.Wait()
}

func (p *gitHTTPSProxy) track(connections ...net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		for _, conn := range connections {
			_ = conn.Close()
		}
		return
	}
	for _, conn := range connections {
		p.tunnels[conn] = struct{}{}
	}
}

func (p *gitHTTPSProxy) untrack(connections ...net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, conn := range connections {
		delete(p.tunnels, conn)
	}
}

func runGitHTTPSCommand(
	policy *httpDestinationPolicy,
	remote string,
	command gitNetworkCommand,
	output gitOutputFunc,
) ([]byte, error) {
	proxy, err := startGitHTTPSProxy(policy)
	if err != nil {
		return nil, err
	}
	defer func() { _ = proxy.Close() }()

	proxyURL := proxy.URL()
	extraConfig := []string{
		"-c", "http.proxy=" + proxyURL,
		"-c", "http." + remote + ".proxy=" + proxyURL,
	}
	cmd := command(remote, extraConfig)
	cmd.Env = gitCommandEnv(proxyURL)
	return output(cmd)
}

func gitCommandEnv(proxyURL string) []string {
	env := gitBaseEnv()
	env = append(env, gitHardenedConfigEnv(httpsScheme)...)
	return append(env,
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,
		"NO_PROXY=",
		"no_proxy=",
	)
}
