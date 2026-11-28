/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"context"
	"encoding/json"
	"math"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/pulumi/capture"
	pulumirpc "github.com/pulumi/pulumi/sdk/v3/proto/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
)

func startForTest(t *testing.T, opts Options) (*Server, pulumirpc.ResourceMonitorClient, pulumirpc.EngineClient) {
	t.Helper()
	if opts.Project == "" {
		opts.Project, opts.Stack = "demo", "prod"
	}
	s, err := Start(&opts)
	require.NoError(t, err)
	t.Cleanup(s.Stop)
	conn, err := grpc.NewClient(s.Addr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return s, pulumirpc.NewResourceMonitorClient(conn), pulumirpc.NewEngineClient(conn)
}

func mustStruct(t *testing.T, m map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	require.NoError(t, err)
	return s
}

func sig(kind string, fields map[string]any) map[string]any {
	out := map[string]any{sigKey: kind}
	for k, v := range fields {
		out[k] = v
	}
	return out
}

func TestRegisterResourceDecodesInputs(t *testing.T) {
	root := t.TempDir()
	s, mon, _ := startForTest(t, Options{Root: root, ProjectDir: root})
	ctx := context.Background()

	stack, err := mon.RegisterResource(ctx, &pulumirpc.RegisterResourceRequest{Type: stackType, Name: "demo-prod"})
	require.NoError(t, err)

	comp, err := mon.RegisterResource(ctx, &pulumirpc.RegisterResourceRequest{
		Type: "demo:index:Assets", Name: "assets", Parent: stack.GetUrn(), Object: &structpb.Struct{},
	})
	require.NoError(t, err)
	assert.Equal(t, "urn:pulumi:prod::demo::demo:index:Assets::assets", comp.GetUrn())

	obj := mustStruct(t, map[string]any{
		"acl":       "private",
		"unknown":   unknownString,
		"secret":    sig(sigSecret, map[string]any{"value": "hunter2"}),
		"outKnown":  sig(sigOutputValue, map[string]any{"value": "known"}),
		"outSecret": sig(sigOutputValue, map[string]any{"value": "x", "secret": true}),
		"outUnk":    sig(sigOutputValue, map[string]any{}),
		"ref":       sig(sigResourceRef, map[string]any{"urn": "urn:pulumi:prod::demo::aws:iam/role:Role::r", "id": "x"}),
		"code":      sig(sigArchive, map[string]any{"path": "./app"}),
		"policy":    sig(sigAsset, map[string]any{"text": "do not keep me"}),
		"nested":    map[string]any{"list": []any{"a", unknownString}},
	})
	main := filepath.Join(root, "infra", "__main__.py")
	bucket, err := mon.RegisterResource(ctx, &pulumirpc.RegisterResourceRequest{
		Type: "aws:s3/bucketV2:BucketV2", Name: "assets", Custom: true, Parent: comp.GetUrn(), Object: obj,
		Provider:             "urn:pulumi:prod::demo::pulumi:providers:aws::east::" + unknownString,
		Dependencies:         []string{"urn:a"},
		PropertyDependencies: map[string]*pulumirpc.RegisterResourceRequest_PropertyDependencies{"ref": {Urns: []string{"urn:a"}}, "acl": {}},
		SourcePosition:       &pulumirpc.SourcePosition{Uri: "file://" + filepath.ToSlash(main), Line: 15, Column: 3},
	})
	require.NoError(t, err)
	assert.Equal(t, "urn:pulumi:prod::demo::demo:index:Assets$aws:s3/bucketV2:BucketV2::assets", bucket.GetUrn())

	snap := s.Snapshot()
	require.Len(t, snap.Resources, 2, "the stack resource is not recorded")
	got := snap.Resources[1]
	assert.True(t, got.Custom)
	assert.Equal(t, comp.GetUrn(), got.Parent)
	assert.Equal(t, map[string]any{
		"acl":       "private",
		"unknown":   map[string]any{capture.MarkerUnknown: true},
		"secret":    map[string]any{capture.MarkerSecret: true},
		"outKnown":  "known",
		"outSecret": map[string]any{capture.MarkerSecret: true},
		"outUnk":    map[string]any{capture.MarkerUnknown: true},
		"ref":       map[string]any{capture.MarkerResourceRef: "urn:pulumi:prod::demo::aws:iam/role:Role::r"},
		"code":      map[string]any{capture.MarkerArchive: true, "path": "./app"},
		"policy":    map[string]any{capture.MarkerAsset: true},
		"nested":    map[string]any{"list": []any{"a", map[string]any{capture.MarkerUnknown: true}}},
	}, got.Inputs)
	assert.Equal(t, map[string][]string{"ref": {"urn:a"}}, got.PropertyDependencies, "empty dependency lists are dropped")
	assert.Equal(t, []string{"urn:a"}, got.Dependencies)
	assert.Contains(t, got.Provider, "pulumi:providers:aws::east")
	require.NotNil(t, got.Source)
	assert.Equal(t, capture.Source{URI: "file://" + filepath.ToSlash(main), Path: "infra/__main__.py", Line: 15, Column: 3}, *got.Source)
}

func TestSourceOutsideRootIsNotAttributed(t *testing.T) {
	root := t.TempDir()
	s, mon, _ := startForTest(t, Options{Root: root})
	outside := "file:///home/user/go/pkg/mod/github.com/pulumi/pulumi-aws/sdk/v6@v6.48.0/go/aws/ec2/subnet.go"
	_, err := mon.RegisterResource(context.Background(), &pulumirpc.RegisterResourceRequest{
		Type: "aws:ec2/subnet:Subnet", Name: "a", Custom: true, Object: &structpb.Struct{},
		SourcePosition: &pulumirpc.SourcePosition{Uri: outside, Line: 280},
	})
	require.NoError(t, err)
	src := s.Snapshot().Resources[0].Source
	require.NotNil(t, src)
	assert.Equal(t, capture.Source{URI: outside}, *src, "no path and no line outside the scan root")
}

func TestResourceCap(t *testing.T) {
	s, mon, _ := startForTest(t, Options{MaxResources: 2})
	ctx := context.Background()
	for i, name := range []string{"a", "b", "c"} {
		_, err := mon.RegisterResource(ctx, &pulumirpc.RegisterResourceRequest{
			Type: "aws:s3/bucket:Bucket", Name: name, Custom: true, Object: &structpb.Struct{},
		})
		if i < 2 {
			require.NoError(t, err)
			continue
		}
		assert.Equal(t, codes.ResourceExhausted, status.Code(err))
	}
	snap := s.Snapshot()
	assert.Len(t, snap.Resources, 2)
	assert.True(t, snap.Capped)
}

func TestInvokePlaceholders(t *testing.T) {
	table := map[string]map[string]any{
		"aws:index/getAvailabilityZones:getAvailabilityZones": {"names": []any{"us-east-1a", "us-east-1b"}, "state": "x"},
	}
	s, mon, _ := startForTest(t, Options{Placeholder: func(tok string) (map[string]any, bool) {
		v, ok := table[tok]
		return v, ok
	}})
	ctx := context.Background()

	resp, err := mon.Invoke(ctx, &pulumirpc.ResourceInvokeRequest{
		Tok:  "aws:index/getAvailabilityZones:getAvailabilityZones",
		Args: mustStruct(t, map[string]any{"state": "available", "filter": unknownString}),
	})
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"names": []any{"us-east-1a", "us-east-1b"}, "state": "available"}, resp.GetReturn().AsMap(),
		"plain args override the placeholder, unknown args do not")

	resp, err = mon.Invoke(ctx, &pulumirpc.ResourceInvokeRequest{Tok: "aws:ec2/getAmi:getAmi", Args: &structpb.Struct{}})
	require.NoError(t, err)
	assert.Empty(t, resp.GetReturn().AsMap())

	snap := s.Snapshot()
	require.Len(t, snap.Invokes, 2)
	assert.True(t, snap.Invokes[0].Placeholder)
	assert.False(t, snap.Invokes[1].Placeholder)
	assert.Equal(t, []any{"us-east-1a", "us-east-1b"}, table["aws:index/getAvailabilityZones:getAvailabilityZones"]["names"],
		"the table is not modified")
	assert.Equal(t, "x", table["aws:index/getAvailabilityZones:getAvailabilityZones"]["state"])
}

func TestReadStackReference(t *testing.T) {
	s, mon, _ := startForTest(t, Options{})
	resp, err := mon.ReadResource(context.Background(), &pulumirpc.ReadResourceRequest{
		Type: stackReferenceType, Name: "network", Id: "acme/network/prod",
	})
	require.NoError(t, err)
	assert.Equal(t, unknownString, resp.GetProperties().GetFields()["outputs"].GetStringValue())
	assert.Equal(t, []capture.Read{{
		URN: "urn:pulumi:prod::demo::pulumi:pulumi:StackReference::network", Type: stackReferenceType, Name: "network", ID: "acme/network/prod",
	}}, s.Snapshot().Reads)
}

func TestSupportsFeatureLogAndUnimplemented(t *testing.T) {
	s, mon, eng := startForTest(t, Options{})
	ctx := context.Background()

	for feature, want := range map[string]bool{"secrets": true, "resourceReferences": true, "outputValues": false, "transforms": false} {
		resp, err := mon.SupportsFeature(ctx, &pulumirpc.SupportsFeatureRequest{Id: feature})
		require.NoError(t, err)
		assert.Equal(t, want, resp.GetHasSupport(), feature)
	}

	_, err := eng.Log(ctx, &pulumirpc.LogRequest{Severity: pulumirpc.LogSeverity_ERROR, Message: "boom"})
	require.NoError(t, err)
	for range maxLogEntries + 5 {
		_, err = eng.Log(ctx, &pulumirpc.LogRequest{Severity: pulumirpc.LogSeverity_INFO, Message: "noise"})
		require.NoError(t, err)
	}

	_, err = mon.GetDeploymentInfo(ctx, &emptypb.Empty{})
	assert.Equal(t, codes.Unimplemented, status.Code(err), "the SDKs fall back to SupportsFeature")
	_, err = mon.Call(ctx, &pulumirpc.ResourceCallRequest{Tok: "aws:x:y"})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	_, err = mon.SignalAndWaitForShutdown(ctx, nil)
	require.NoError(t, err)

	snap := s.Snapshot()
	assert.Len(t, snap.Logs, maxLogEntries, "logs are bounded")
	assert.Equal(t, "info", snap.Logs[0].Severity)
	assert.Equal(t, []string{"/pulumirpc.ResourceMonitor/Call"}, snap.Unimplemented, "capability probes are not recorded")
}

func TestFileURIPath(t *testing.T) {
	for _, tc := range []struct {
		uri     string
		windows bool
		want    string
	}{
		{"file:///home/u/infra/main.py", false, "/home/u/infra/main.py"},
		{"file://localhost/home/u/main.py", false, "/home/u/main.py"},
		{"file://server/share/main.py", false, ""},
		{"file://C:/x/y.py", false, ""},
		{"file:///C:/x/y.py", false, "/C:/x/y.py"},
		{"file://C:/x/y.py", true, "C:/x/y.py"},
		{"file://d:/x/y.py", true, "d:/x/y.py"},
		{"file:///C:/x/y.py", true, "C:/x/y.py"},
		{"file://localhost/C:/x/y.py", true, "C:/x/y.py"},
		{"file://server/share/y.py", true, ""},
		{"file:///x/y.py", true, "/x/y.py"},
	} {
		u, err := url.Parse(tc.uri)
		require.NoError(t, err, tc.uri)
		assert.Equal(t, tc.want, fileURIPath(u.Host, u.Path, tc.windows), "%s (windows=%v)", tc.uri, tc.windows)
	}
}

// TestNonFiniteNumbersAreUnknown checks that NaN and infinities, which JSON
// cannot encode, are recorded as unknown values.
func TestNonFiniteNumbersAreUnknown(t *testing.T) {
	got := decodeStruct(&structpb.Struct{Fields: map[string]*structpb.Value{
		"nan":    structpb.NewNumberValue(math.NaN()),
		"inf":    structpb.NewNumberValue(math.Inf(1)),
		"negInf": structpb.NewNumberValue(math.Inf(-1)),
		"finite": structpb.NewNumberValue(1.5),
		"list":   structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{structpb.NewNumberValue(math.NaN())}}),
	}})
	unknown := map[string]any{capture.MarkerUnknown: true}
	assert.Equal(t, unknown, got["nan"])
	assert.Equal(t, unknown, got["inf"])
	assert.Equal(t, unknown, got["negInf"])
	assert.Equal(t, []any{unknown}, got["list"])
	assert.Equal(t, 1.5, got["finite"])
	_, err := json.Marshal(got)
	assert.NoError(t, err)
}
