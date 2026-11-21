/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package engine is a minimal, in-process stand-in for the Pulumi engine.
//
// It serves the two gRPC services a Pulumi language SDK talks to,
// ResourceMonitor and Engine, on 127.0.0.1. A program pointed at it through
// PULUMI_MONITOR and PULUMI_ENGINE runs as in a preview: every resource it
// declares is recorded and answered as "created" with no ID and no outputs, so
// every value derived from another resource stays unknown. Nothing is ever
// created: there is no Pulumi CLI, no provider plugin, no state and no cloud
// access involved.
package engine

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/pulumi/capture"
	pulumirpc "github.com/pulumi/pulumi/sdk/v3/proto/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DefaultMaxResources is the default cap on resources recorded per evaluation.
const DefaultMaxResources = 10000

// maxLogEntries bounds the engine log messages kept for diagnostics.
const maxLogEntries = 200

// maxMessageSize is the largest gRPC message accepted from a program (property
// maps of large resources, such as inline policies, exceed the 4 MiB default).
const maxMessageSize = 64 << 20

// Options configure one fake engine, serving one project × stack evaluation.
type Options struct {
	Project string
	Stack   string
	// Root is the scan root. Source positions are made relative to it, and
	// positions outside it are not used for attribution.
	Root string
	// ProjectDir is the directory holding Pulumi.yaml (for project:// URIs).
	ProjectDir string
	// MaxResources caps the recorded resources; 0 means DefaultMaxResources.
	MaxResources int
	// Placeholder returns the outputs to answer an invoke (data source) with.
	// When nil or when it returns false, the invoke gets an empty result.
	Placeholder func(token string) (map[string]any, bool)
	// OnCapped is called once, when the program goes over MaxResources.
	OnCapped func()
}

// LogEntry is one message the program sent to the engine log.
type LogEntry struct {
	Severity string
	Message  string
}

// Snapshot is what the program declared so far.
type Snapshot struct {
	Resources []capture.Resource
	Invokes   []capture.Invoke
	Reads     []capture.Read
	Logs      []LogEntry
	// Capped is true when the program declared more than MaxResources.
	Capped bool
	// Unimplemented lists the engine RPCs the program called that the fake
	// engine does not implement.
	Unimplemented []string
}

// Server is a running fake engine.
type Server struct {
	opts  Options
	roots []string
	lis   net.Listener
	srv   *grpc.Server

	mu   sync.Mutex
	snap Snapshot

	cappedOnce sync.Once
}

// Start listens on an ephemeral 127.0.0.1 port and serves the fake engine.
func Start(opts *Options) (*Server, error) {
	s := &Server{opts: *opts}
	if s.opts.MaxResources <= 0 {
		s.opts.MaxResources = DefaultMaxResources
	}
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("fake pulumi engine: listen: %w", err)
	}
	s.lis = lis
	if s.opts.Root != "" {
		root := filepath.Clean(s.opts.Root)
		s.roots = append(s.roots, root)
		if resolved, err := filepath.EvalSymlinks(root); err == nil && resolved != root {
			s.roots = append(s.roots, resolved)
		}
	}
	s.srv = grpc.NewServer(
		grpc.MaxRecvMsgSize(maxMessageSize),
		grpc.UnknownServiceHandler(s.unknownService),
		grpc.UnaryInterceptor(s.recordUnimplemented),
	)
	pulumirpc.RegisterResourceMonitorServer(s.srv, &monitor{s: s})
	pulumirpc.RegisterEngineServer(s.srv, &engineService{s: s})
	go func() { _ = s.srv.Serve(lis) }()
	return s, nil
}

// Addr is the address to pass in PULUMI_MONITOR and PULUMI_ENGINE.
func (s *Server) Addr() string { return s.lis.Addr().String() }

// Stop stops serving and ends in-flight calls.
func (s *Server) Stop() { s.srv.Stop() }

// Snapshot returns a copy of what was recorded.
func (s *Server) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.snap
	out.Resources = append([]capture.Resource(nil), s.snap.Resources...)
	out.Invokes = append([]capture.Invoke(nil), s.snap.Invokes...)
	out.Reads = append([]capture.Read(nil), s.snap.Reads...)
	out.Logs = append([]LogEntry(nil), s.snap.Logs...)
	out.Unimplemented = append([]string(nil), s.snap.Unimplemented...)
	return out
}

func (s *Server) noteUnimplemented(method string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.snap.Unimplemented {
		if m == method {
			return
		}
	}
	s.snap.Unimplemented = append(s.snap.Unimplemented, method)
}

// capabilityProbes are the RPCs the Go and Python SDKs call at startup and
// handle Unimplemented for (they fall back to SupportsFeature). Answering them
// as unimplemented is expected, so they are not recorded.
var capabilityProbes = map[string]bool{
	pulumirpc.ResourceMonitor_GetDeploymentInfo_FullMethodName: true,
}

// recordUnimplemented notes the RPCs of known services that the fake engine
// does not implement, so that a failed evaluation can say which one it hit.
func (s *Server) recordUnimplemented(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	resp, err := handler(ctx, req)
	if status.Code(err) == codes.Unimplemented && !capabilityProbes[info.FullMethod] {
		s.noteUnimplemented(info.FullMethod)
	}
	return resp, err
}

func (s *Server) unknownService(_ any, stream grpc.ServerStream) error {
	method, _ := grpc.MethodFromServerStream(stream)
	s.noteUnimplemented(method)
	return errUnimplemented(method)
}

func (s *Server) urn(qualifiedType, name string) string {
	return fmt.Sprintf("urn:pulumi:%s::%s::%s::%s", s.opts.Stack, s.opts.Project, qualifiedType, name)
}
