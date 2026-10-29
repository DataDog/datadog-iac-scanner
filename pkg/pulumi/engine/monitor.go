/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"context"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/pulumi/capture"
	pulumirpc "github.com/pulumi/pulumi/sdk/v3/proto/go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	stackType          = "pulumi:pulumi:Stack"
	stackReferenceType = "pulumi:pulumi:StackReference"
)

// features the fake engine really implements. "outputValues" stays off, so
// inputs arrive as plain values (unknowns as the unknown sentinel) rather than
// as output wrappers.
var features = map[string]bool{
	"secrets":            true,
	"resourceReferences": true,
}

func errUnimplemented(method string) error {
	return status.Errorf(codes.Unimplemented, "the scanner's fake Pulumi engine does not implement %s", method)
}

type monitor struct {
	pulumirpc.UnimplementedResourceMonitorServer
	s *Server
}

func (m *monitor) SupportsFeature(_ context.Context, r *pulumirpc.SupportsFeatureRequest) (*pulumirpc.SupportsFeatureResponse, error) {
	return &pulumirpc.SupportsFeatureResponse{HasSupport: features[r.GetId()]}, nil
}

// qualifiedType is the URN type of a resource: Pulumi prefixes it with the
// parent's type chain, except for children of the stack.
func qualifiedType(parentURN, typ string) string {
	parts := strings.SplitN(parentURN, "::", 4) //nolint:mnd // urn:pulumi:<stack>::<project>::<type>::<name>
	if len(parts) < 4 || parts[2] == stackType {
		return typ
	}
	return parts[2] + "$" + typ
}

func (m *monitor) RegisterResource(_ context.Context, r *pulumirpc.RegisterResourceRequest) (*pulumirpc.RegisterResourceResponse, error) {
	urn := m.s.urn(qualifiedType(r.GetParent(), r.GetType()), r.GetName())
	if r.GetType() == stackType {
		return &pulumirpc.RegisterResourceResponse{Urn: urn, Object: &structpb.Struct{}}, nil
	}
	res := capture.Resource{
		URN:          urn,
		Type:         r.GetType(),
		Name:         r.GetName(),
		Custom:       r.GetCustom(),
		Remote:       r.GetRemote(),
		Parent:       r.GetParent(),
		Provider:     r.GetProvider(),
		Inputs:       decodeStruct(r.GetObject()),
		Dependencies: r.GetDependencies(),
		Source:       m.s.sourceOf(r.GetSourcePosition()),
	}
	for prop, deps := range r.GetPropertyDependencies() {
		if len(deps.GetUrns()) == 0 {
			continue
		}
		if res.PropertyDependencies == nil {
			res.PropertyDependencies = map[string][]string{}
		}
		res.PropertyDependencies[prop] = deps.GetUrns()
	}

	m.s.mu.Lock()
	if len(m.s.snap.Resources) >= m.s.opts.MaxResources {
		m.s.snap.Capped = true
		m.s.mu.Unlock()
		return nil, status.Errorf(codes.ResourceExhausted,
			"the scanner's fake Pulumi engine records at most %d resources per stack", m.s.opts.MaxResources)
	}
	m.s.snap.Resources = append(m.s.snap.Resources, res)
	m.s.mu.Unlock()

	// Preview semantics: no ID and no outputs, so every output of this
	// resource stays unknown for the rest of the program.
	return &pulumirpc.RegisterResourceResponse{Urn: urn, Object: &structpb.Struct{}}, nil
}

func (m *monitor) RegisterResourceOutputs(context.Context, *pulumirpc.RegisterResourceOutputsRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

// Invoke answers a data source with the placeholder outputs for its token,
// merged with the call's plain arguments (data sources echo their inputs), or
// with an empty result when there is no placeholder.
func (m *monitor) Invoke(_ context.Context, r *pulumirpc.ResourceInvokeRequest) (*pulumirpc.ResourceInvokeResponse, error) {
	args := decodeStruct(r.GetArgs())
	var ph map[string]any
	found := false
	if m.s.opts.Placeholder != nil {
		ph, found = m.s.opts.Placeholder(r.GetTok())
	}
	out := map[string]any{}
	if found {
		for k, v := range ph {
			out[k] = v
		}
		for k, v := range args {
			if isPlain(v) {
				out[k] = v
			}
		}
	}
	ret, err := structpb.NewStruct(out)
	if err != nil {
		ret, found = &structpb.Struct{}, false
	}

	m.s.mu.Lock()
	m.s.snap.Invokes = append(m.s.snap.Invokes, capture.Invoke{
		Token:       r.GetTok(),
		Args:        args,
		Placeholder: found,
		Source:      m.s.sourceOf(r.GetSourcePosition()),
	})
	m.s.mu.Unlock()
	return &pulumirpc.ResourceInvokeResponse{Return: ret}, nil
}

// ReadResource (StackReference, Resource.get) answers with no properties, so
// everything read from another stack or an existing resource stays unknown,
// as in a preview without state.
func (m *monitor) ReadResource(_ context.Context, r *pulumirpc.ReadResourceRequest) (*pulumirpc.ReadResourceResponse, error) {
	urn := m.s.urn(qualifiedType(r.GetParent(), r.GetType()), r.GetName())
	m.s.mu.Lock()
	m.s.snap.Reads = append(m.s.snap.Reads, capture.Read{URN: urn, Type: r.GetType(), Name: r.GetName(), ID: r.GetId()})
	m.s.mu.Unlock()

	props := &structpb.Struct{Fields: map[string]*structpb.Value{}}
	if r.GetType() == stackReferenceType {
		props.Fields["name"] = structpb.NewStringValue(r.GetId())
		props.Fields["outputs"] = structpb.NewStringValue(unknownString)
		props.Fields["secretOutputNames"] = structpb.NewListValue(&structpb.ListValue{})
	}
	return &pulumirpc.ReadResourceResponse{Urn: urn, Properties: props}, nil
}

// SignalAndWaitForShutdown has nothing to wait for: no operation is pending.
func (m *monitor) SignalAndWaitForShutdown(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

type engineService struct {
	pulumirpc.UnimplementedEngineServer
	s *Server

	mu   sync.Mutex
	root string
}

// Log keeps the last messages: the Python launcher reports program errors here.
func (e *engineService) Log(_ context.Context, r *pulumirpc.LogRequest) (*emptypb.Empty, error) {
	e.s.mu.Lock()
	defer e.s.mu.Unlock()
	e.s.snap.Logs = append(e.s.snap.Logs, LogEntry{
		Severity: strings.ToLower(r.GetSeverity().String()),
		Message:  r.GetMessage(),
	})
	if n := len(e.s.snap.Logs); n > maxLogEntries {
		e.s.snap.Logs = e.s.snap.Logs[n-maxLogEntries:]
	}
	return &emptypb.Empty{}, nil
}

func (e *engineService) GetRootResource(context.Context, *pulumirpc.GetRootResourceRequest) (*pulumirpc.GetRootResourceResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return &pulumirpc.GetRootResourceResponse{Urn: e.root}, nil
}

func (e *engineService) SetRootResource(
	_ context.Context, r *pulumirpc.SetRootResourceRequest,
) (*pulumirpc.SetRootResourceResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.root = r.GetUrn()
	return &pulumirpc.SetRootResourceResponse{}, nil
}
